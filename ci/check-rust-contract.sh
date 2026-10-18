#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
devenv_file=$repository_root/devenv.nix
flake_file=$repository_root/flake.nix
workflow_file=$repository_root/.github/workflows/flake.yml
ci_contract_file=$repository_root/ci/check-flake-contract.sh

for check in fmt clippy test doc; do
  grep -Fq "tasks.\"check:$check\".exec = \"bash ci/check-rust.sh $check\";" "$devenv_file"
done

for binding in 'format fmt' 'clippy clippy' 'tests test' 'docs doc'; do
  read -r check command <<< "$binding"
  grep -Fq "$check = runRustCheck \"$command\";" "$flake_file"
done

# shellcheck disable=SC2016 # Match Nix interpolation literally.
grep -Fq 'bash ${repositorySrc}/ci/check-rust.sh ${command}' "$flake_file"
grep -Fq 'env.craneLib.mkCargoDerivation' "$flake_file"
grep -Fq 'inherit (env) cargoArtifacts;' "$flake_file"
grep -Fq 'export CARGO_PROFILE' "$flake_file"
grep -Fq './ci/check-flake-contract.sh' "$workflow_file"
grep -Fq 'nix flake check -L --no-update-lock-file' "$ci_contract_file"

if grep -Eq 'cargo (fmt|clippy|nextest run|doc)' "$devenv_file"; then
  printf 'devenv must invoke the canonical ci/check-rust.sh commands\n' >&2
  exit 1
fi

cargo() {
  printf 'argument:%s\n' "$@"
  printf 'NEXTEST_TEST_THREADS=%s\n' "${NEXTEST_TEST_THREADS:-unset}"
}
export -f cargo

recorded_nextest_call=$(
  CARGO_PROFILE=profiling NIX_BUILD_CORES=3 \
    bash "$repository_root/ci/check-rust.sh" test
)
expected_nextest_call=$'argument:nextest\nargument:run\nargument:--cargo-profile\nargument:profiling\nargument:--locked\nargument:--workspace\nargument:--all-features\nNEXTEST_TEST_THREADS=3'
if [[ "$recorded_nextest_call" != "$expected_nextest_call" ]]; then
  printf 'canonical nextest arguments differ from the expected Cargo profile and Nix thread limit:\n%s\n' \
    "$recorded_nextest_call" >&2
  exit 1
fi

recorded_native_call=$(
  CARGO_PROFILE=profiling NARJAR_NATIVE_TEST_FILE=/nix/store/fixture \
    bash "$repository_root/ci/check-rust.sh" native-http
)
expected_native_call=$'argument:nextest\nargument:run\nargument:--cargo-profile\nargument:profiling\nargument:--locked\nargument:--all-features\nargument:--test\nargument:cli\nargument:--run-ignored=only\nargument:-E\nargument:test(cli_tests::native_http)\nNEXTEST_TEST_THREADS=unset'
if [[ "$recorded_native_call" != "$expected_native_call" ]]; then
  printf 'native HTTP acceptance command differs:\n%s\n' "$recorded_native_call" >&2
  exit 1
fi
grep -Fq 'nix run -L --no-update-lock-file .#native-http-tests' "$workflow_file"

printf 'local, flake, and CI Rust check commands share ci/check-rust.sh\n'
