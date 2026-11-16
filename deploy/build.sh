#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 0 ]] || fail "Usage: bash deploy/build.sh"
[[ "$(uname -s)" == Linux ]] || fail "Build directly on the approved Ubuntu host."
[[ "$EUID" -ne 0 ]] || fail "Build as your ordinary account, not root."
require_commands cargo rustc sha256sum
cd -- "$PROJECT_DIR"
# update.sh runs this script as one of its steps and supplies the framing.
if [[ -z "${UI_NESTED:-}" ]]; then
    banner 'Script Audit MCP - Build (no service changes)'
    plan_steps 1
    step 'Build release binary'
fi
detail Toolchain "$(rustc --version)"
detail '' "$(cargo --version)"
detail Features 'database, mcp, http (locked dependencies)'
info 'Compiling; this can take a minute...'
run_indented cargo build --locked --release --no-default-features --features database,mcp,http
ARTIFACT="$PROJECT_DIR/target/release/script-audit-mcp"
ok 'Release build finished.'
detail Artifact "$ARTIFACT"
detail '' "sha256 $(sha256sum -- "$ARTIFACT" | awk '{print $1}')"
detail '' "$(stat -c '%s bytes' -- "$ARTIFACT")"
if [[ -z "${UI_NESTED:-}" ]]; then
    result SUCCESS 'The running service was not changed. Run deploy/update.sh to install this build.'
fi
