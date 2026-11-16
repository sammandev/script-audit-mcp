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
PUBLIC_LISTENER=10.176.2.139:39064
PRIVATE_LISTENER=127.0.0.1:39065
# shellcheck source=deploy/ui.sh
source "$DEPLOY_DIR/ui.sh"

fail() {
    error "$*"
    # Inside a multi-step task, close with the same summary an ERR trap prints.
    if ((UI_STEPS > 0)); then
        if [[ -n "${BACKUP:-}" ]]; then
            detail Backup "$BACKUP" >&2
            hint "Restore if needed: bash deploy/rollback.sh $BACKUP"
        fi
        result FAILED "Stopped during step $UI_STEP/$UI_STEPS: ${UI_STEP_TITLE:-startup}." >&2
    fi
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
    ok "Running as operator $(id -un) on $(uname -n); sudo session is ready."
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
    ok "Installation matches the approved unit, account, listener and file layout."
    detail Unit "$UNIT"
    detail Binary "$BINARY"
    detail Environment "$ENV_FILE"
    detail "Nginx site" "$NGINX_SITE"
}

# Usage: describe_binary LABEL PATH
describe_binary() {
    local checksum metadata
    checksum="$(sudo sha256sum -- "$2" | awk '{print $1}')"
    metadata="$(sudo stat -c '%s bytes, modified %y' -- "$2" | sed 's/\.[0-9]* / /')"
    detail "$1" "sha256 $checksum"
    detail '' "$metadata"
}

lock_deployment() {
    require_commands flock
    # Keep all operators using the same uploaded source directory.
    exec 9>"$PROJECT_DIR/.deploy.lock"
    flock -n 9 || fail "Another update or rollback is running from this source directory."
    ok "Deployment lock acquired ($PROJECT_DIR/.deploy.lock)."
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
    ok "Rollback backup created."
    detail Backup "$BACKUP"
    if sudo test -d "$UNIT.d"; then
        detail Contains 'binary, unit, environment file, Nginx site, unit drop-ins'
    else
        detail Contains 'binary, unit, environment file, Nginx site'
    fi
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
    local attempt reason listeners='' smoke=''
    for attempt in {1..10}; do
        if ! sudo systemctl is-active --quiet "$SERVICE"; then
            reason='service is not active yet'
        elif ! listeners="$(check_listeners 2>&1)"; then
            reason='listeners are not ready yet'
        elif ! smoke="$(bash "$DEPLOY_DIR/mcp-smoke.sh" 2>&1)"; then
            reason='MCP protocol smoke check failed'
        else
            ok "Service is active (verification attempt $attempt/10)."
            printf '%s\n' "$listeners"
            printf '%s\n' "$smoke" | sed 's/^/  /'
            return 0
        fi
        if ((attempt < 10)); then
            # Restarts take a moment; early attempts are expected to wait.
            info "Attempt $attempt/10: $reason; retrying in 2 seconds."
            sleep 2
        fi
    done
    error "Attempt 10/10: $reason."
    [[ -z "$listeners" ]] || printf '%s\n' "$listeners" >&2
    [[ -z "$smoke" ]] || printf '%s\n' "$smoke" | sed 's/^/  /' >&2
    fail "Release verification failed. Review logs with debug.sh and use the printed backup with rollback.sh."
}

check_listeners() {
    local listeners
    listeners="$(sudo ss -H -ltnp '( sport = :39064 or sport = :39065 )')" || {
        error 'Cannot inspect MCP listeners.'
        return 1
    }
    if [[ -z "$listeners" ]]; then
        info 'No process is listening on port 39064 or 39065.'
    else
        printf '       %-24s %s\n' 'Listener' 'Process'
        printf '%s\n' "$listeners" | awk '{
            line = $0; name = ""; count = 0
            while (match(line, /\("[^"]+",pid=[0-9]+/)) {
                entry = substr(line, RSTART + 2, RLENGTH - 2)
                split(entry, parts, "\",pid=")
                if (name == "") { name = parts[1]; pid = parts[2] }
                count++
                line = substr(line, RSTART + RLENGTH)
            }
            if (name == "") summary = "(unknown process)"
            else if (count == 1) summary = sprintf("%s (pid %s)", name, pid)
            else summary = sprintf("%s (%d processes)", name, count)
            printf "       %-24s %s\n", $4, summary
        }'
    fi
    if ! printf '%s\n' "$listeners" | awk -v private="$PRIVATE_LISTENER" -v public="$PUBLIC_LISTENER" '
        $4 ~ /:39065$/ {
            private_count++
            if ($4 != private || $0 !~ /script-audit-mc/) bad=1
        }
        $4 ~ /:39064$/ {
            public_count++
            if ($4 != public || $0 !~ /nginx/) bad=1
        }
        END { exit (bad || private_count != 1 || public_count != 1) ? 1 : 0 }
    '; then
        error 'Listener addresses or process names do not match the approved MCP/Nginx deployment.'
        hint "Expected exactly: $PRIVATE_LISTENER -> script-audit-mcp, $PUBLIC_LISTENER -> nginx."
        return 1
    fi
    ok "Listeners match the approved deployment ($PRIVATE_LISTENER private, $PUBLIC_LISTENER via Nginx)."
}
