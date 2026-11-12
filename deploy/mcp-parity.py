#!/usr/bin/env python3
"""Run MCP/web readiness parity against a disposable PostgreSQL test database."""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


def redact(output: str, secrets: Sequence[str]) -> str:
    for secret in secrets:
        if secret:
            output = output.replace(secret, "<redacted>")
    return output


def run_command(
    command: list[str], cwd: Path, environment: dict[str, str], label: str
) -> int:
    try:
        result = subprocess.run(
            command, cwd=cwd, env=environment, capture_output=True, text=True
        )
    except OSError as error:
        print(f"ERROR: could not start {label}: {error.strerror}", file=sys.stderr)
        return 1

    output = redact(
        result.stdout + result.stderr,
        [environment.get("TEST_DATABASE_URL", ""), environment.get("PGPASSWORD", "")],
    )
    if output:
        print(output, end="" if output.endswith("\n") else "\n")
    if result.returncode:
        print(
            f"ERROR: {label} failed with exit code {result.returncode}.",
            file=sys.stderr,
        )
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--web-repo",
        required=True,
        type=Path,
        help="path to the Web_Program_Functions_Database checkout",
    )
    options = parser.parse_args()

    if not os.environ.get("TEST_DATABASE_URL"):
        parser.error("set TEST_DATABASE_URL to an authorized disposable test database")

    web_repo = options.web_repo.expanduser().resolve()
    backend = web_repo / "backend"
    migrations = backend / "internal" / "db" / "postgres_migrations"
    if not (backend / "go.mod").is_file() or not (backend / "cmd" / "server" / "main.go").is_file():
        parser.error("--web-repo must contain backend/go.mod and backend/cmd/server/main.go")
    if not migrations.is_dir() or not list(migrations.glob("*.sql")):
        parser.error("--web-repo has no PostgreSQL migration SQL files")

    repository = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    environment["WEB_POSTGRES_MIGRATIONS_DIR"] = str(migrations)

    with tempfile.TemporaryDirectory(prefix="mcp-readiness-parity-") as directory:
        binary_name = "webprogfndb-server.exe" if os.name == "nt" else "webprogfndb-server"
        binary = Path(directory) / binary_name
        environment["WEB_API_BINARY"] = str(binary)

        build_status = run_command(
            ["go", "build", "-o", str(binary), "./cmd/server"],
            backend,
            environment,
            "Go API build",
        )
        if build_status:
            return build_status

        return run_command(
            [
                "cargo",
                "test",
                "--lib",
                "postgres_readiness_matches_mcp_list_functions",
                "--",
                "--ignored",
                "--nocapture",
            ],
            repository,
            environment,
            "MCP/web readiness parity test",
        )


if __name__ == "__main__":
    sys.exit(main())
