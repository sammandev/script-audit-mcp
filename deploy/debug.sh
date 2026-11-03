#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -le 1 ]] || fail "Usage: bash deploy/debug.sh [journal-since-time]"
operator_only
require_commands journalctl
if [[ "$#" -eq 1 ]]; then
    since="$1"
else
    since="$(sudo systemctl show "$SERVICE" --property=ExecMainStartTimestamp --value --no-pager)"
    [[ -n "$since" ]] || fail "No recorded start time. Supply a time, for example: '30 minutes ago'."
fi
printf 'WARNING: Logs may contain database connection details. Review locally and redact secrets before sharing.\n' >&2
sudo systemctl show "$SERVICE" --no-pager \
    -p ActiveState -p SubState -p MainPID -p NRestarts -p ExecMainStatus
sudo journalctl -u "$SERVICE" --since "$since" -n 100 --no-pager
