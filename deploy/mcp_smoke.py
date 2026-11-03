"""Operator-run MCP checks; curl supplies bounded HTTP requests without proxy use."""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

EXPECTED_TOOLS = {
    "list_functions", "get_function", "suggest_criteria", "compose_line",
    "validate_line", "validate_ini_bundle", "compare_plan_to_bundle",
    "compose_ini_bundle",
}


def rpc_result(body: str, request_id: int) -> dict[str, Any]:
    if body.lstrip().startswith("{"):
        messages = [json.loads(body)]
    else:
        messages = []
        for event in re.split(r"\r?\n\r?\n", body):
            data = "\n".join(
                line[5:].removeprefix(" ")
                for line in event.splitlines() if line.startswith("data:")
            )
            if data.strip():
                messages.append(json.loads(data))
    matches = [
        message for message in messages
        if isinstance(message, dict) and type(message.get("id")) is int
        and message.get("id") == request_id
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one JSON-RPC response for id {request_id}.")
    message = matches[0]
    if message.get("jsonrpc") != "2.0" or "error" in message:
        raise ValueError(f"JSON-RPC request {request_id} failed; inspect the response locally.")
    result = message.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"JSON-RPC request {request_id} has no object result.")
    return result


class Client:
    def __init__(self, url: str) -> None:
        self.url = url
        self.session = ""
        self.protocol = "2025-06-18"

    def request(
        self, method: str, payload: dict[str, Any] | None = None,
        extra_headers: tuple[str, ...] = (),
    ) -> tuple[int, dict[str, str], str]:
        with tempfile.TemporaryDirectory(prefix="mcp-smoke-") as directory:
            headers_path = Path(directory) / "headers"
            body_path = Path(directory) / "body"
            command = [
                "curl", "--noproxy", "*", "--max-time", "20", "--silent",
                "--show-error", "--request", method, "--dump-header", str(headers_path),
                "--output", str(body_path), "--write-out", "%{http_code}", self.url,
                "-H", "Accept: application/json, text/event-stream",
            ]
            if self.session:
                command += [
                    "-H", f"Mcp-Session-Id: {self.session}",
                    "-H", f"MCP-Protocol-Version: {self.protocol}",
                ]
            for header in extra_headers:
                command += ["-H", header]
            if payload is not None:
                command += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(payload)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=25, check=True)
            headers = {}
            for line in headers_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("HTTP/"):
                    headers.clear()
                elif ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.lower()] = value.strip()
            return int(completed.stdout), headers, body_path.read_text(encoding="utf-8")

    def post(self, payload: dict[str, Any], expected_status: int) -> str:
        status, headers, body = self.request("POST", payload)
        if status != expected_status:
            raise ValueError(f"Expected HTTP {expected_status}, received {status}.")
        if payload.get("method") == "initialize":
            self.session = headers.get("mcp-session-id", "")
            if not self.session or re.search(r"[\s\x00-\x1f\x7f]", self.session):
                raise ValueError("Missing or invalid MCP session ID.")
        return body


def check(client: Client, tool: str | None, arguments: dict[str, Any]) -> None:
    try:
        initialized = rpc_result(client.post({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": client.protocol, "capabilities": {},
                "clientInfo": {"name": "operator-smoke", "version": "1"},
            },
        }, 200), 1)
        protocol = initialized.get("protocolVersion")
        if not isinstance(protocol, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", protocol):
            raise ValueError("Missing or invalid negotiated protocol version.")
        client.protocol = protocol
        capabilities = initialized.get("capabilities")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
            raise ValueError("Initialization did not advertise tools.")
        client.post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 202)
        result = rpc_result(client.post({
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {},
        }, 200), 2)
        tools = result.get("tools")
        if not isinstance(tools, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("name"), str)
            for item in tools
        ):
            raise ValueError("tools/list returned an invalid tool list.")
        names = {item["name"] for item in tools}
        if names != EXPECTED_TOOLS or len(tools) != len(EXPECTED_TOOLS):
            raise ValueError("Tool discovery does not match the eight expected tools.")
        print(f"MCP initialization and all eight tools passed (protocol {client.protocol}).")
        if tool:
            result = rpc_result(client.post({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }, 200), 3)
            if result.get("isError") is True or not isinstance(result.get("content"), list):
                raise ValueError(f"Tool {tool} failed or returned an invalid result.")
            print(json.dumps(result, indent=2))
        for header in ("Origin: http://untrusted.invalid", "Host: untrusted.invalid"):
            status, _, _ = client.request("GET", extra_headers=(header,))
            if status != 403:
                raise ValueError(f"Proxy rejection failed for {header.split(':', 1)[0]}: HTTP {status}.")
        print("Proxy rejected untrusted Origin and Host with HTTP 403.")
    finally:
        if client.session:
            pending_error = sys.exc_info()[0] is not None
            try:
                status, _, _ = client.request("DELETE")
                if status not in (200, 202, 204):
                    raise ValueError(f"MCP session cleanup failed: HTTP {status}.")
            except (ValueError, OSError, subprocess.SubprocessError):
                if not pending_error:
                    raise
                print("ERROR: Session cleanup also failed; the original check failure is retained.", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://10.176.2.139:39064/mcp")
    parser.add_argument("--tool", choices=sorted(EXPECTED_TOOLS))
    parser.add_argument("--arguments", default="{}", help="JSON object for the optional tool call")
    options = parser.parse_args()
    try:
        arguments = json.loads(options.arguments)
        if not isinstance(arguments, dict):
            raise ValueError("--arguments must be a JSON object.")
        if options.arguments != "{}" and not options.tool:
            raise ValueError("--arguments requires --tool.")
        check(Client(options.url), options.tool, arguments)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Do not include curl stderr or response bodies that may expose connection details.
        print(f"ERROR: {type(error).__name__}: {error}" if isinstance(error, ValueError)
              else f"ERROR: {type(error).__name__}; inspect connectivity and server logs locally.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
