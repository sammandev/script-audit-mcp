#!/usr/bin/env bash
# Shared helpers for operator-run updates of the existing systemd installation.
set -Eeuo pipefail
export SYSTEMD_PAGER=cat
export SYSTEMD_COLORS=0

DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$DEPLOY_DIR/.." && pwd)"
SERVICE=script-audit-mcp
INSTALL_DIR=/opt/script-audit-mcp
BINARY="$INSTALL_DIR/bin/script-audit-mcp"
ENV_FILE="$INSTALL_DIR/etc/script-audit-mcp.env"
UNIT=/etc/systemd/system/script-audit-mcp.service
NGINX_SITE=/etc/nginx/sites-available/script-audit-mcp
BACKUP_ROOT="$INSTALL_DIR/backups"

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_commands() {
    local command
    for command in "$@"; do
        command -v "$command" >/dev/null || fail "Required command is missing: $command"
    done
}

require_smoke_runtime() {
    require_commands python3 curl
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "ERROR: Python 3.10 or newer is required.")'
}

operator_only() {
    [[ "$(uname -s)" == Linux ]] || fail "Run this task directly on the approved Ubuntu host."
    [[ "$EUID" -ne 0 ]] || fail "Run as your ordinary operator account, not sudo bash. The script invokes sudo when needed."
    require_commands sudo systemctl
    sudo -v
}

check_installation() {
    local actual
    actual="$(sudo systemctl show "$SERVICE" --property=FragmentPath --value --no-pager)"
    [[ "$actual" == "$UNIT" ]] || fail "Unexpected unit path: $actual"
    actual="$(sudo systemctl show "$SERVICE" --property=User --value --no-pager)"
    [[ "$actual" == script-audit ]] || fail "Unexpected service account: $actual"
    actual="$(sudo systemctl show "$SERVICE" --property=Group --value --no-pager)"
    [[ "$actual" == script-audit ]] || fail "Unexpected service group: $actual"
    actual="$(sudo systemctl show "$SERVICE" --property=ExecStart --value --no-pager)"
    [[ "$actual" == *"argv[]=$BINARY --http --host 127.0.0.1 --port 39065 ;"* ]] ||
        fail "ExecStart does not match the approved binary and loopback listener. Review the installed unit locally."
    actual="$(sudo systemctl show "$SERVICE" --property=EnvironmentFiles --value --no-pager)"
    [[ "$actual" == "$ENV_FILE (ignore_errors=no)" ]] ||
        fail "EnvironmentFiles does not match the protected production file."
    sudo test -f "$BINARY"
    sudo test ! -L "$BINARY"
    sudo test -f "$ENV_FILE"
    sudo test -f "$NGINX_SITE"
}

lock_deployment() {
    require_commands flock
    # Keep all operators using the same uploaded source directory.
    exec 9>"$PROJECT_DIR/.deploy.lock"
    flock -n 9 || fail "Another update or rollback is running from this source directory."
}

make_backup() {
    sudo install -d -o root -g root -m 0700 "$BACKUP_ROOT"
    BACKUP="$(sudo mktemp -d "$BACKUP_ROOT/$(date -u +%Y%m%d-%H%M%S)-XXXXXX")"
    sudo cp -a -- "$BINARY" "$BACKUP/script-audit-mcp"
    sudo cp -a -- "$UNIT" "$BACKUP/script-audit-mcp.service"
    sudo cp -a -- "$ENV_FILE" "$BACKUP/script-audit-mcp.env"
    sudo cp -a -- "$NGINX_SITE" "$BACKUP/nginx.conf"
    if sudo test -d "$UNIT.d"; then
        sudo cp -a -- "$UNIT.d" "$BACKUP/script-audit-mcp.service.d"
    fi
    printf 'Rollback backup: %s\n' "$BACKUP"
}

replace_binary() {
    local source="$1"
    STAGED="$(sudo mktemp "$INSTALL_DIR/bin/.script-audit-mcp.XXXXXX")" || return 1
    sudo install -o root -g root -m 0755 -- "$source" "$STAGED" || return 1
    sudo mv -fT -- "$STAGED" "$BINARY" || return 1
    STAGED=
}

cleanup_staged() {
    if [[ -n "${STAGED:-}" ]]; then
        sudo rm -f -- "$STAGED"
    fi
}

verify_release() {
    local attempt
    for attempt in {1..10}; do
        if sudo systemctl is-active --quiet "$SERVICE" &&
            check_listeners &&
            bash "$DEPLOY_DIR/mcp-smoke.sh"; then
            printf 'Protocol checks passed. Reconnect clients and verify known catalog content, changed behavior, and the existing web app.\n'
            return 0
        fi
        printf 'Verification attempt %s/10 failed; retrying in 2 seconds.\n' "$attempt" >&2
        sleep 2
    done
    fail "Release verification failed. Review current logs with debug.sh and use the printed backup with rollback.sh."
}

check_listeners() {
    local listeners
    listeners="$(sudo ss -H -ltnp '( sport = :39064 or sport = :39065 )')" || {
        printf 'ERROR: Cannot inspect MCP listeners.\n' >&2
        return 1
    }
    printf '%s\n' "$listeners"
    if ! printf '%s\n' "$listeners" | awk '
        $4 ~ /:39065$/ {
            private_count++
            if ($4 != "127.0.0.1:39065" || $0 !~ /script-audit-mc/) bad=1
        }
        $4 ~ /:39064$/ {
            public_count++
            if ($4 != "10.176.2.139:39064" || $0 !~ /nginx/) bad=1
        }
        END { exit (bad || private_count != 1 || public_count != 1) ? 1 : 0 }
    '; then
        printf 'ERROR: Listener addresses or process names do not match the approved MCP/Nginx deployment.\n' >&2
        return 1
    fi
}
