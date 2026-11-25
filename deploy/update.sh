#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 0 ]] || fail "Usage: bash deploy/update.sh"
banner 'Script Audit MCP - Update'
plan_steps 6
trap 'report_failure Update "$LINENO" "${BACKUP:-}"' ERR

step 'Preflight checks'
operator_only
require_commands cargo rustc nginx ss awk readlink sha256sum stat
require_smoke_runtime
ok 'Required commands are available (cargo, rustc, nginx, ss, awk, readlink, python3 >= 3.10, curl).'
check_installation
lock_deployment
sudo systemctl is-active --quiet "$SERVICE" || fail "Service is not active. Diagnose it before updating."
ok "Service $SERVICE is active."
describe_binary 'Current binary' "$BINARY"
run_indented sudo nginx -t
ok 'Nginx configuration test passed.'
sudo systemctl reload nginx
ok 'Nginx configuration reloaded.'
check_listeners
trap cleanup_staged EXIT

step 'Build release binary'
UI_NESTED=1 bash "$DEPLOY_DIR/build.sh"

step 'Back up current installation'
make_backup

step 'Install new binary'
replace_binary "$PROJECT_DIR/target/release/script-audit-mcp"
ok 'Binary replaced atomically (staged copy, then rename).'
describe_binary 'New binary' "$BINARY"

step 'Restart service'
sudo systemctl restart "$SERVICE"
ok "Restart requested for $SERVICE."

step 'Verify release'
verify_release

result SUCCESS 'Update installed and verified.'
detail Backup "${BACKUP:-}"
detail Rollback "bash deploy/rollback.sh ${BACKUP:-}"
printf '\n  Next: reconnect MCP clients, check known catalog content, retest the\n'
printf '  changed behavior, and confirm the existing web app still works.\n'
