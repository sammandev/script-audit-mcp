#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 0 ]] || fail "Usage: bash deploy/update.sh"
operator_only
require_commands cargo rustc nginx ss awk
require_smoke_runtime
check_installation
lock_deployment
sudo systemctl is-active --quiet "$SERVICE" || fail "Service is not active. Diagnose it before updating."
sudo nginx -t
trap cleanup_staged EXIT
trap 'printf "ERROR: Update failed at line %s. Backup: %s. No automatic rollback was attempted.\n" "$LINENO" "${BACKUP:-not created}" >&2' ERR

bash "$DEPLOY_DIR/build.sh"
make_backup
replace_binary "$PROJECT_DIR/target/release/script-audit-mcp"
sudo systemctl restart "$SERVICE"
verify_release
