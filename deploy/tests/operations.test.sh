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
    elif [[ "$1" == systemctl && "$2" == is-active && "$3" == --quiet && "$4" == nginx ]]; then
        [[ "${TEST_NGINX_INACTIVE:-no}" != yes ]]
    elif [[ "$1" == test ]]; then
        if [[ "${TEST_MISSING_NGINX_LINK:-no}" == yes && "$2" == -L && "$3" == /etc/nginx/sites-enabled/script-audit-mcp ]]; then
            return 1
        fi
        return 0
    elif [[ "$1" == readlink ]]; then
        printf '%s\n' "$NGINX_SITE"
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
if (TEST_MISSING_NGINX_LINK=yes; check_installation); then
    fail 'Missing enabled Nginx site was accepted.'
fi
echo 'PASS: missing enabled Nginx site rejected'
if (TEST_NGINX_INACTIVE=yes; check_installation); then
    fail 'Inactive Nginx service was accepted.'
fi
echo 'PASS: inactive Nginx service rejected'
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

SS_CALLS="$(mktemp)"
sudo() {
    if [[ "$1" == systemctl ]]; then
        return 0
    elif [[ "$1" == ss ]]; then
        # The first inspection happens before MCP has bound its private port.
        if [[ -s "$SS_CALLS" ]]; then
            printf 'LISTEN 0 128 127.0.0.1:39065 0.0.0.0:* users:(("script-audit-mc",pid=1,fd=6))\n'
        fi
        echo call >>"$SS_CALLS"
        printf 'LISTEN 0 511 10.176.2.139:39064 0.0.0.0:* users:(("nginx",pid=2,fd=9),("nginx",pid=3,fd=9))\n'
    else
        return 1
    fi
}
bash() { echo '[ OK ] mocked smoke check'; }
sleep() { :; }
output="$(verify_release 2>&1)"
rm -f -- "$SS_CALLS"
unset -f bash sleep
[[ "$output" == *'Attempt 1/10: listeners are not ready yet; retrying in 2 seconds.'* ]]
[[ "$output" != *'[FAIL]'* && "$output" != *ERROR* ]]
[[ "$output" == *'nginx (2 processes)'* && "$output" == *'mocked smoke check'* ]]
echo 'PASS: transient listener startup is reported as a retry, not a failure'

PROXY_DIR="$(mktemp -d)"
BUILD_PROXY_FILE="$PROXY_DIR/.env.proxy"
output="$(NO_PROXY=inherited; load_build_proxy; printf '%s' "$NO_PROXY")"
[[ "$output" == inherited ]]
echo 'PASS: missing proxy profile keeps inherited shell settings'
printf "https_proxy='http://user:s3cret%%24@proxy.invalid:80'\n" >"$BUILD_PROXY_FILE"
chmod 600 "$BUILD_PROXY_FILE"
output="$(NO_PROXY=inherited; load_build_proxy; bash -c 'printf "|%s|%s|" "$https_proxy" "${NO_PROXY:-unset}"')"
[[ "$output" == *'|http://user:s3cret%24@proxy.invalid:80|unset|' ]]
[[ "${output%%|*}" != *s3cret* ]]
echo 'PASS: private proxy profile is exported to cargo, replaces inherited settings, and is not printed'
chmod 644 "$BUILD_PROXY_FILE"
if (load_build_proxy) >/dev/null 2>&1; then
    fail 'World-readable proxy profile was accepted.'
fi
echo 'PASS: proxy profile without mode 600 rejected'
printf "https_proxy='replace_me'\n" >"$BUILD_PROXY_FILE"
chmod 600 "$BUILD_PROXY_FILE"
if (load_build_proxy) >/dev/null 2>&1; then
    fail 'Placeholder proxy profile was accepted.'
fi
echo 'PASS: placeholder proxy profile rejected'
rm -rf -- "$PROXY_DIR"
echo 'All shell helper tests passed.'
