#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 0 ]] || fail "Usage: bash deploy/status.sh"
operator_only
require_commands ss nginx sha256sum awk
check_installation
sudo systemctl show "$SERVICE" --no-pager \
    -p ActiveState -p SubState -p MainPID -p NRestarts \
    -p ExecMainStartTimestamp -p ExecMainStatus -p MemoryCurrent
sudo sha256sum "$BINARY"
check_listeners
sudo nginx -t
sudo systemctl is-active --quiet "$SERVICE" || fail "MCP service is not active."
printf 'Service checks passed; run mcp-smoke.sh to verify the protocol and proxy rejection paths.\n'
