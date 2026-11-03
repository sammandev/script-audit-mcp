import contextlib
import importlib.util
import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "mcp_smoke", Path(__file__).resolve().parents[1] / "mcp_smoke.py"
)
assert SPEC is not None and SPEC.loader is not None
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def response(request_id, result):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})


class FakeClient(smoke.Client):
    def __init__(self):
        super().__init__("http://example.invalid/mcp")
        self.calls = []
        self.tools = [{"name": name} for name in sorted(smoke.EXPECTED_TOOLS)]
        self.origin_status = 403
        self.cleanup_status = 200
        self.tool_error = False
        self.notify_status = 202
        self.initialize_status = 200
        self.session_header = "test-session"

    def request(self, method, payload=None, extra_headers=()):
        self.calls.append((method, payload, extra_headers, self.session, self.protocol))
        if method == "DELETE":
            return self.cleanup_status, {}, ""
        if method == "GET":
            return self.origin_status, {}, ""
        name = payload["method"]
        if name == "initialize":
            return self.initialize_status, {"mcp-session-id": self.session_header}, response(1, {
                "protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
            })
        if name == "notifications/initialized":
            return self.notify_status, {}, ""
        if name == "tools/list":
            return 200, {}, response(2, {"tools": self.tools})
        if name == "tools/call":
            return 200, {}, response(3, {"isError": self.tool_error, "content": []})
        raise AssertionError(name)


class SmokeTests(unittest.TestCase):
    def run_check(self, client, tool=None):
        with contextlib.redirect_stdout(io.StringIO()):
            smoke.check(client, tool, {})

    def test_json_and_sse(self):
        body = response(1, {"capabilities": {}})
        for encoded in (body, f"data:\nid: 0\n\n data: ignored\n\ndata: {body}\n\n",
                        f"data: {body}\r\n\r\n"):
            with self.subTest(encoded=encoded):
                self.assertEqual(smoke.rpc_result(encoded, 1), {"capabilities": {}})

    def test_multiline_sse(self):
        self.assertEqual(smoke.rpc_result(
            'data: {"jsonrpc":"2.0","id":1,\ndata: "result":{"ok":true}}\n\n', 1
        ), {"ok": True})

    def test_rpc_errors_and_missing_results(self):
        for message in ({}, {"jsonrpc": "2.0", "id": 1, "error": {}},
                        {"jsonrpc": "2.0", "id": 1, "result": []},
                        {"jsonrpc": "1.0", "id": 1, "result": {}}):
            with self.subTest(message=message), self.assertRaises(ValueError):
                smoke.rpc_result(json.dumps(message), 1)

    def test_duplicate_rpc_response(self):
        body = response(1, {})
        with self.assertRaises(ValueError):
            smoke.rpc_result(f"data: {body}\n\ndata: {body}\n\n", 1)

    def test_boolean_id_is_not_an_integer_request_id(self):
        with self.assertRaises(ValueError):
            smoke.rpc_result('{"jsonrpc":"2.0","id":true,"result":{}}', 1)

    def test_full_handshake_and_negotiated_version(self):
        client = FakeClient()
        self.run_check(client)
        self.assertEqual(client.calls[1][3:], ("test-session", "2025-11-25"))
        self.assertEqual(client.calls[-1][0], "DELETE")
        self.assertEqual(sum(call[0] == "GET" for call in client.calls), 2)

    def test_missing_tool_fails_and_cleans_up(self):
        client = FakeClient()
        client.tools.pop()
        with self.assertRaisesRegex(ValueError, "eight expected"):
            self.run_check(client)
        self.assertEqual(client.calls[-1][0], "DELETE")

    def test_duplicate_tool_fails(self):
        client = FakeClient()
        client.tools.append(client.tools[0])
        with self.assertRaisesRegex(ValueError, "eight expected"):
            self.run_check(client)

    def test_bad_notification_status(self):
        client = FakeClient()
        client.notify_status = 200
        with self.assertRaisesRegex(ValueError, "Expected HTTP 202"):
            self.run_check(client)
        self.assertEqual(client.calls[-1][0], "DELETE")

    def test_missing_session_fails(self):
        client = FakeClient()
        client.session_header = ""
        with self.assertRaisesRegex(ValueError, "session ID"):
            self.run_check(client)

    def test_non_200_initialize_fails(self):
        client = FakeClient()
        client.initialize_status = 503
        with self.assertRaisesRegex(ValueError, "received 503"):
            self.run_check(client)

    def test_tool_failure_is_not_success(self):
        client = FakeClient()
        client.tool_error = True
        with self.assertRaisesRegex(ValueError, "Tool get_function failed"):
            self.run_check(client, "get_function")
        self.assertEqual(client.calls[-1][0], "DELETE")

    def test_proxy_failure_is_not_success(self):
        client = FakeClient()
        client.origin_status = 200
        with self.assertRaisesRegex(ValueError, "Proxy rejection failed"):
            self.run_check(client)

    def test_cleanup_failure_is_not_success(self):
        client = FakeClient()
        client.cleanup_status = 500
        with self.assertRaisesRegex(ValueError, "cleanup failed"):
            self.run_check(client)

    def test_cleanup_does_not_mask_original_error(self):
        client = FakeClient()
        client.origin_status = 200
        client.cleanup_status = 500
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaisesRegex(ValueError, "Proxy rejection failed"):
                self.run_check(client)
        self.assertIn("cleanup also failed", errors.getvalue())

    def test_curl_is_bounded_and_bypasses_proxy(self):
        def fake_run(command, **kwargs):
            self.assertEqual(command[command.index("--noproxy") + 1], "*")
            self.assertEqual(command[command.index("--max-time") + 1], "20")
            self.assertEqual(kwargs["timeout"], 25)
            self.assertTrue(kwargs["check"])
            Path(command[command.index("--dump-header") + 1]).write_text(
                "HTTP/1.1 200 OK\nMcp-Session-Id: test-session\n", encoding="utf-8"
            )
            Path(command[command.index("--output") + 1]).write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="200", stderr="")
        with patch.object(smoke.subprocess, "run", side_effect=fake_run):
            status, headers, body = smoke.Client("http://example.invalid/mcp").request("POST", {})
        self.assertEqual((status, headers["mcp-session-id"], body), (200, "test-session", "{}"))


if __name__ == "__main__":
    unittest.main()
