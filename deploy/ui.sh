#!/usr/bin/env bash
# Terminal output helpers shared by the operator deploy scripts.
# Colour is used only on an interactive terminal and is disabled by NO_COLOR.

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != dumb ]]; then
    UI_BOLD=$'\e[1m' UI_DIM=$'\e[2m' UI_RED=$'\e[31m' UI_GREEN=$'\e[32m'
    UI_YELLOW=$'\e[33m' UI_CYAN=$'\e[36m' UI_RESET=$'\e[0m'
else
    UI_BOLD='' UI_DIM='' UI_RED='' UI_GREEN='' UI_YELLOW='' UI_CYAN='' UI_RESET=''
fi
UI_STEP=0
UI_STEPS=0
UI_STEP_TITLE=''
UI_STARTED=$SECONDS
UI_RULE='------------------------------------------------------------------------'
UI_HEAVY_RULE='========================================================================'

banner() {
    printf '\n%s%s\n  %s\n%s%s\n' "$UI_BOLD" "$UI_HEAVY_RULE" "$1" "$UI_HEAVY_RULE" "$UI_RESET"
    detail Host "${HOSTNAME:-$(uname -n)}"
    detail Operator "$(id -un 2>/dev/null || printf unknown)"
    detail Started "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    detail Source "$PROJECT_DIR"
    detail Revision "$(source_revision)"
}

source_revision() {
    local revision branch changed
    if ! command -v git >/dev/null ||
        ! revision="$(git -C "$PROJECT_DIR" log -1 --date=short --format='%h %s (%cd)' 2>/dev/null)"; then
        printf 'unknown (not a readable git checkout)'
        return 0
    fi
    branch="$(git -C "$PROJECT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || printf '?')"
    changed="$(git -C "$PROJECT_DIR" status --porcelain --untracked-files=no 2>/dev/null | wc -l || true)"
    printf '%s [%s]' "$revision" "$branch"
    if [[ "${changed// /}" != 0 ]]; then
        printf ', %s modified tracked file(s)' "${changed// /}"
    fi
}

# Usage: plan_steps TOTAL
plan_steps() {
    UI_STEPS="$1"
    UI_STEP=0
}

step() {
    UI_STEP=$((UI_STEP + 1))
    UI_STEP_TITLE="$*"
    printf '\n%s[%s/%s] %s%s\n' "$UI_BOLD$UI_CYAN" "$UI_STEP" "$UI_STEPS" "$*" "$UI_RESET"
}

detail() {
    if [[ -n "$1" ]]; then
        printf '       %s%-14s%s %s\n' "$UI_DIM" "$1:" "$UI_RESET" "$2"
    else
        printf '       %-14s %s\n' '' "$2"
    fi
}

ok() {
    printf '  %s[ OK ]%s %s\n' "$UI_GREEN" "$UI_RESET" "$*"
}

info() {
    printf '  [INFO] %s\n' "$*"
}

warn() {
    printf '  %s[WARN]%s %s\n' "$UI_YELLOW" "$UI_RESET" "$*" >&2
}

error() {
    printf '  %s[FAIL]%s %s\n' "$UI_RED" "$UI_RESET" "$*" >&2
}

hint() {
    printf '         -> %s\n' "$*" >&2
}

# Prefix command output so it reads as part of the current step.
indent() {
    sed 's/^/       | /'
}

# Run a command, showing its combined output indented; returns the command status.
run_indented() {
    "$@" 2>&1 | indent
}

elapsed() {
    local seconds=$((SECONDS - UI_STARTED))
    printf '%dm %02ds' $((seconds / 60)) $((seconds % 60))
}

# Usage: result SUCCESS|FAILED "message"
result() {
    local colour="$UI_GREEN"
    [[ "$1" == SUCCESS ]] || colour="$UI_RED"
    printf '\n%s%s%s\n' "$UI_BOLD" "$UI_RULE" "$UI_RESET"
    printf '  %sRESULT: %s%s  %s(elapsed %s)%s\n' "$UI_BOLD$colour" "$1" "$UI_RESET" "$UI_DIM" "$(elapsed)" "$UI_RESET"
    [[ -z "${2:-}" ]] || printf '  %s\n' "$2"
    printf '%s%s%s\n' "$UI_BOLD" "$UI_RULE" "$UI_RESET"
}

# Print a failure summary from an ERR trap: report_failure TASK LINE [backup]
report_failure() {
    local task="$1" line="$2" backup="${3:-}"
    {
        printf '\n'
        error "$task failed at line $line during step $UI_STEP/$UI_STEPS: ${UI_STEP_TITLE:-startup}."
        if [[ -n "$backup" ]]; then
            detail Backup "$backup"
            hint "Inspect logs first: bash deploy/debug.sh"
            hint "Restore if needed:  bash deploy/rollback.sh $backup"
        else
            detail Backup 'not created (installed binary was not changed)'
            hint "Inspect logs: bash deploy/debug.sh"
        fi
        result FAILED "No automatic rollback was attempted."
    } >&2
}

# Format `systemctl show` KEY=VALUE lines as aligned, human-readable details.
show_properties() {
    awk -F= '{
        key = $1; value = substr($0, length($1) + 2)
        if (key == "MemoryCurrent" && value ~ /^[0-9]+$/) value = sprintf("%.1f MiB", value / 1048576)
        if (value == "") value = "(none)"
        printf "       %-24s %s\n", key ":", value
    }'
}
