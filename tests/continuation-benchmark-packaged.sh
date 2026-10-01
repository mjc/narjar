#!/usr/bin/env bash
set -Eeuo pipefail

launcher=$1
source_root=$2
test_root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-benchmark-launcher.XXXXXX")
trap 'rm -rf -- "$test_root"' EXIT

fake_bin="$test_root/bin"
mkdir -p "$fake_bin"
fake_nix="$fake_bin/nix"
fake_narjar="$fake_bin/narjar"
expected_nix_args="$test_root/nix-args"
expected_expression="$source_root/benchmarks/bincache.nix"
expected_output=/nix/store/fake-bincache

help=$("$launcher" --help)
[[ "$help" == *"--resolve-bincache-only"* ]]

printf '#!%s\n' "$BASH" >"$fake_nix"
cat >>"$fake_nix" <<'FAKE_NIX'
set -Eeuo pipefail
printf '%s\n' "$@" >"$NARJAR_BENCHMARK_TEST_NIX_ARGS"
[[ "$1" == build ]]
[[ "$2" == --no-write-lock-file ]]
[[ "$3" == --no-link ]]
[[ "$4" == --print-out-paths ]]
[[ "$5" == --impure ]]
[[ "$6" == --file ]]
[[ "$7" == "$NARJAR_BENCHMARK_TEST_EXPRESSION" ]]
[[ -r "$7" ]]
[[ -r "$(dirname -- "$7")/bincache-no-compression.patch" ]]
printf '%s\n' "$NARJAR_BENCHMARK_TEST_OUTPUT"
FAKE_NIX
printf '#!%s\nexit 0\n' "$BASH" >"$fake_narjar"
chmod 0700 "$fake_nix" "$fake_narjar"

resolved=$(
  NARJAR_BIN="$fake_narjar" \
    NARJAR_NIX_BIN="$fake_nix" \
    NARJAR_BENCHMARK_TEST_NIX_ARGS="$expected_nix_args" \
    NARJAR_BENCHMARK_TEST_EXPRESSION="$expected_expression" \
    NARJAR_BENCHMARK_TEST_OUTPUT="$expected_output" \
    "$launcher" --output "$test_root/resolved" --resolve-bincache-only
)
[[ "$resolved" == "$expected_output/bin/bincache" ]]
expected_args=$(printf 'build\n--no-write-lock-file\n--no-link\n--print-out-paths\n--impure\n--file\n%s' "$expected_expression")
[[ "$(<"$expected_nix_args")" == "$expected_args" ]]

missing_expression="$test_root/missing.nix"
if NARJAR_BIN="$fake_narjar" NARJAR_BINCACHE_EXPR="$missing_expression" \
  "$launcher" --output "$test_root/missing-expression" --resolve-bincache-only \
  >"$test_root/missing-expression.out" 2>"$test_root/missing-expression.err"; then
  printf 'FAIL: missing Bincache expression was accepted\n' >&2
  exit 1
fi
grep -Fq "NARJAR_BINCACHE_EXPR is not readable: $missing_expression" "$test_root/missing-expression.err"

mkdir -p "$test_root/no-patch"
printf 'builtins.abort "fake expression"\n' >"$test_root/no-patch/bincache.nix"
if NARJAR_BIN="$fake_narjar" NARJAR_BINCACHE_EXPR="$test_root/no-patch/bincache.nix" \
  "$launcher" --output "$test_root/missing-patch" --resolve-bincache-only \
  >"$test_root/missing-patch.out" 2>"$test_root/missing-patch.err"; then
  printf 'FAIL: missing sibling patch was accepted\n' >&2
  exit 1
fi
grep -Fq 'Bincache patch is missing beside NARJAR_BINCACHE_EXPR:' "$test_root/missing-patch.err"

printf 'packaged continuation benchmark launcher input tests passed\n'
