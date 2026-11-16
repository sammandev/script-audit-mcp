#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 0 ]] || fail "Usage: bash deploy/status.sh"
banner 'Script Audit MCP - Status (read-only)'
plan_steps 5

step 'Installation'
operator_only
require_commands ss nginx sha256sum stat awk
check_installation

step 'Service'
sudo systemctl show "$SERVICE" --no-pager \
    -p ActiveState -p SubState -p MainPID -p NRestarts \
    -p ExecMainStartTimestamp -p ExecMainStatus -p MemoryCurrent | show_properties
sudo systemctl is-active --quiet "$SERVICE" || fail "MCP service is not active. Inspect logs with: bash deploy/debug.sh"
ok "Service $SERVICE is active."

step 'Installed binary'
describe_binary Binary "$BINARY"

step 'Listeners'
check_listeners

step 'Nginx'
run_indented sudo nginx -t
ok 'Nginx configuration test passed.'

result SUCCESS 'Service checks passed.'
printf '  Next: bash deploy/mcp-smoke.sh   (protocol and proxy rejection checks)\n'
