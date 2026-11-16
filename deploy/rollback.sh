#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 1 ]] || fail "Usage: bash deploy/rollback.sh /opt/script-audit-mcp/backups/EXACT_BACKUP_DIRECTORY"
banner 'Script Audit MCP - Rollback'
plan_steps 5
trap 'report_failure Rollback "$LINENO" "${BACKUP:-}"' ERR

step 'Preflight checks'
operator_only
require_commands realpath nginx ss awk sha256sum stat
require_smoke_runtime
ok 'Required commands are available (nginx, ss, awk, realpath, python3 >= 3.10, curl).'
check_installation
lock_deployment
SELECTED="$(sudo realpath -e -- "$1")"
[[ "$(dirname -- "$SELECTED")" == "$BACKUP_ROOT" ]] ||
    fail "Select one direct backup directory under $BACKUP_ROOT."
sudo test -d "$SELECTED"
sudo test -f "$SELECTED/script-audit-mcp"
sudo test ! -L "$SELECTED/script-audit-mcp"
ok 'Selected backup is a direct child of the backup root and contains a regular binary.'

step 'Confirm restore'
detail Selected "$SELECTED"
describe_binary 'Current binary' "$BINARY"
describe_binary 'Backup binary' "$SELECTED/script-audit-mcp"
warn 'This restores the binary only, restarts MCP and discards client sessions.'
info 'Configuration, the Nginx site and the database remain unchanged.'
read -r -p '  Type ROLLBACK to continue: ' confirmation
[[ "$confirmation" == ROLLBACK ]] || fail "Rollback cancelled. Nothing was changed."
run_indented sudo nginx -t
ok 'Nginx configuration test passed.'
trap cleanup_staged EXIT

step 'Back up current installation'
make_backup

step 'Restore binary and restart'
sudo systemctl stop "$SERVICE"
ok "Service $SERVICE stopped."
replace_binary "$SELECTED/script-audit-mcp"
ok 'Backup binary installed atomically (staged copy, then rename).'
sudo systemctl start "$SERVICE"
ok "Service $SERVICE started."

step 'Verify release'
verify_release

result SUCCESS 'Rollback installed and verified.'
detail Restored "$SELECTED"
detail 'Undo backup' "${BACKUP:-}"
printf '\n  Next: reconnect MCP clients and confirm the restored behavior.\n'
