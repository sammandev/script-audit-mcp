#!/usr/bin/env bash
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
[[ "$#" -eq 0 ]] || fail "Usage: bash deploy/build.sh"
[[ "$(uname -s)" == Linux ]] || fail "Build directly on the approved Ubuntu host."
[[ "$EUID" -ne 0 ]] || fail "Build as your ordinary account, not root."
require_commands cargo rustc
cd -- "$PROJECT_DIR"
rustc --version
cargo --version
cargo build --locked --release --no-default-features --features database,mcp,http
