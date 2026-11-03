#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 1 ]] || fail "Usage: bash deploy/rollback.sh /opt/script-audit-mcp/backups/EXACT_BACKUP_DIRECTORY"
operator_only
require_commands realpath nginx ss awk
require_smoke_runtime
check_installation
lock_deployment
SELECTED="$(sudo realpath -e -- "$1")"
[[ "$(dirname -- "$SELECTED")" == "$BACKUP_ROOT" ]] ||
    fail "Select one direct backup directory under $BACKUP_ROOT."
sudo test -d "$SELECTED"
sudo test -f "$SELECTED/script-audit-mcp"
sudo test ! -L "$SELECTED/script-audit-mcp"
printf 'Restore binary from %s. This restarts MCP and discards client sessions. Configuration and database remain unchanged.\n' "$SELECTED"
read -r -p 'Type ROLLBACK to continue: ' confirmation
[[ "$confirmation" == ROLLBACK ]] || fail "Rollback cancelled."
sudo nginx -t
trap cleanup_staged EXIT
trap 'printf "ERROR: Rollback failed at line %s. Recovery backup: %s. Inspect service before retrying.\n" "$LINENO" "${BACKUP:-not created}" >&2' ERR
make_backup
sudo systemctl stop "$SERVICE"
replace_binary "$SELECTED/script-audit-mcp"
sudo systemctl start "$SERVICE"
verify_release
