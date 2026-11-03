#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"

# No real sudo, systemd, database, or network calls are made by these tests.
sudo() {
    if [[ "$1" == systemctl && "$2" == show ]]; then
        case "$4" in
            --property=FragmentPath) echo "$UNIT" ;;
            --property=User) echo script-audit ;;
            --property=Group) echo script-audit ;;
            --property=EnvironmentFiles) echo "$ENV_FILE (ignore_errors=no)" ;;
            --property=ExecStart) echo "{ argv[]=$BINARY --http --host ${TEST_HOST:-127.0.0.1} --port 39065 ; }" ;;
            *) return 1 ;;
        esac
    elif [[ "$1" == test ]]; then
        return 0
    elif [[ "$1" == ss ]]; then
        printf 'LISTEN 0 128 %s:39065 0.0.0.0:* users:(("script-audit-mc",pid=1,fd=6))\n' "${TEST_HOST:-127.0.0.1}"
        if [[ "${TEST_MISSING_PROXY:-no}" != yes ]]; then
            printf 'LISTEN 0 511 10.176.2.139:39064 0.0.0.0:* users:(("nginx",pid=2,fd=9))\n'
        fi
    else
        echo "Unexpected sudo call: $*" >&2
        return 1
    fi
}

check_installation
echo 'PASS: approved installation accepted'
if (TEST_HOST=0.0.0.0; check_installation); then
    fail "Unexpected ExecStart was accepted."
fi
echo 'PASS: public MCP ExecStart rejected'
check_listeners
if (TEST_HOST=0.0.0.0; check_listeners); then
    fail "Public MCP listener was accepted."
fi
echo 'PASS: public MCP listener rejected'
if (TEST_MISSING_PROXY=yes; check_listeners); then
    fail "Missing Nginx listener was accepted."
fi
echo 'PASS: missing Nginx listener rejected'

TRACE=()
sudo() { TRACE+=("$*"); [[ "$1" != mktemp ]] || printf '/approved/staged-file\n'; }
replace_binary /approved/new-binary
[[ "${TRACE[0]}" == "install -o root -g root -m 0755 -- /approved/new-binary /approved/staged-file" ]]
[[ "${TRACE[1]}" == "mv -fT -- /approved/staged-file $BINARY" ]]
[[ -z "$STAGED" ]]
echo 'PASS: staged binary replaced by rename, not in-place write'

sudo() { return 1; }
if (set -e; replace_binary /approved/missing-binary); then
    fail "Staging failure did not stop replacement."
fi
echo 'PASS: staging failure stops replacement'

sudo() {
    if [[ "$1" == mktemp ]]; then
        printf '/approved/staged-file\n'
    elif [[ "$1" == install ]]; then
        return 1
    else
        fail "Replacement continued after install failure."
    fi
}
if (replace_binary /approved/missing-binary); then
    fail "Install failure did not stop replacement."
fi
echo 'PASS: install failure prevents rename'
echo 'All shell helper tests passed.'
