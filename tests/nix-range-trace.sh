#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TEST_BINARY=$(mktemp)
trap 'rm -f -- "$TEST_BINARY"' EXIT

rustc --test -D warnings "$ROOT/scripts/nix-range-trace.rs" -o "$TEST_BINARY"
"$TEST_BINARY"

help=$("$ROOT/scripts/nix-range-trace" --help 2>&1)
[[ "$help" == *"--cache-url"* ]]
[[ "$help" == *"--range-size"* ]]

echo "nix range trace tests passed"
