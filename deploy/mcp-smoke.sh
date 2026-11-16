#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
require_smoke_runtime
exec python3 "$DEPLOY_DIR/mcp_smoke.py" "$@"
