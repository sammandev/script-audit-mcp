#!/usr/bin/env bash
set -Eeuo pipefail
TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == --run ]]; then
    WORK="${WORKFLOW_TEST_WORK:?}"
else
    WORK="$(mktemp -d)"
    trap 'rm -f -- "$WORK/trace"; rmdir -- "$WORK"' EXIT
fi

run_task() (
    set -Eeuo pipefail
    task="$1"
    scenario="$2"
    shift 2
    SERVICE=script-audit-mcp
    DEPLOY_DIR="$TEST_DIR/.."
    PROJECT_DIR=/approved/source
    BACKUP_ROOT=/opt/script-audit-mcp/backups
    TRACE_FILE="$WORK/trace"
    : >"$TRACE_FILE"

    log() { printf '%s\n' "$*" >>"$TRACE_FILE"; }
    fail() { echo "ERROR: $*" >&2; exit 1; }
    operator_only() { log operator; }
    require_commands() { :; }
    require_smoke_runtime() { :; }
    check_installation() { log preflight; [[ "$scenario" != preflight-fails ]]; }
    lock_deployment() { log lock; }
    cleanup_staged() { log cleanup; }
    make_backup() { log backup; BACKUP="$BACKUP_ROOT/new-backup"; }
    replace_binary() { log replace; [[ "$scenario" != replace-fails ]]; }
    verify_release() {
        log verify
        [[ "$scenario" != smoke-fails ]] || fail "Mock smoke failure."
    }
    bash() { log build; [[ "$scenario" != build-fails ]]; }
    sudo() {
        if [[ "$1" == systemctl ]]; then
            log "$2"
            return 0
        elif [[ "$1" == nginx ]]; then
            log nginx
            return 0
        elif [[ "$1" == realpath ]]; then
            printf '%s\n' "$4"
        elif [[ "$1" == test ]]; then
            return 0
        else
            fail "Unexpected privileged call: $*"
        fi
    }
    # Run the unchanged task body with helpers mocked instead of sourcing common.sh.
    source <(tail -n +3 "$TEST_DIR/../$task.sh") "$@"
)

if [[ "${1:-}" == --run ]]; then
    shift
    run_task "$@"
    exit
fi

run_case() {
    WORKFLOW_TEST_WORK="$WORK" command bash "$TEST_DIR/workflow.test.sh" --run "$@"
}

assert_trace() {
    local expected="$1" actual
    actual="$(paste -sd ',' "$WORK/trace")"
    [[ "$actual" == "$expected" ]] || {
        printf 'ERROR: expected %s; received %s\n' "$expected" "$actual" >&2
        exit 1
    }
}

run_case update success
assert_trace 'operator,preflight,lock,is-active,nginx,build,backup,replace,restart,verify,cleanup'
echo 'PASS: update builds before backup and replacement, then verifies restart'

if run_case update preflight-fails; then exit 1; fi
assert_trace 'operator,preflight'
echo 'PASS: preflight failure makes no deployment changes'

if run_case update build-fails; then exit 1; fi
assert_trace 'operator,preflight,lock,is-active,nginx,build,cleanup'
echo 'PASS: build failure leaves installed binary untouched'

if run_case update replace-fails; then exit 1; fi
assert_trace 'operator,preflight,lock,is-active,nginx,build,backup,replace,cleanup'
echo 'PASS: replacement failure does not restart service'

if run_case update smoke-fails; then exit 1; fi
assert_trace 'operator,preflight,lock,is-active,nginx,build,backup,replace,restart,verify,cleanup'
echo 'PASS: smoke failure returns failure without automatic rollback'

run_case rollback success /opt/script-audit-mcp/backups/old-backup <<<ROLLBACK
assert_trace 'operator,preflight,lock,nginx,backup,stop,replace,start,verify,cleanup'
echo 'PASS: confirmed rollback backs up current binary before stopping'

if run_case rollback success /tmp/not-approved <<<ROLLBACK; then exit 1; fi
assert_trace 'operator,preflight,lock'
echo 'PASS: backup outside approved directory rejected'

if run_case rollback success /opt/script-audit-mcp/backups/old-backup <<<NO; then exit 1; fi
assert_trace 'operator,preflight,lock'
echo 'PASS: unconfirmed rollback makes no deployment changes'
echo 'All workflow tests passed.'
