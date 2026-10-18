#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'Usage: %s {fmt|clippy|test|native-http|doc}\n' "${0##*/}" >&2
}

check=${1:-}
cargo_profile_args=()
nextest_profile_args=()
case "${CARGO_PROFILE:-}" in
  "") ;;
  release)
    cargo_profile_args=(--release)
    nextest_profile_args=(--release)
    ;;
  *)
    cargo_profile_args=(--profile "$CARGO_PROFILE")
    nextest_profile_args=(--cargo-profile "$CARGO_PROFILE")
    ;;
esac

case "$check" in
  fmt)
    cargo fmt --all -- --check
    ;;
  clippy)
    cargo clippy "${cargo_profile_args[@]}" --locked --workspace --all-targets --all-features -- -D warnings
    ;;
  test)
    if [[ -n ${NIX_BUILD_CORES:-} ]]; then
      export NEXTEST_TEST_THREADS=$NIX_BUILD_CORES
    fi
    cargo nextest run "${nextest_profile_args[@]}" --locked --workspace --all-features
    ;;
  native-http)
    : "${NARJAR_NATIVE_TEST_FILE:?native HTTP tests require an immutable store fixture}"
    cargo nextest run "${nextest_profile_args[@]}" --locked --all-features --test cli \
      --run-ignored=only -E 'test(cli_tests::native_http)'
    ;;
  doc)
    RUSTDOCFLAGS="-D warnings" cargo test --doc "${cargo_profile_args[@]}" --locked --workspace --all-features
    RUSTDOCFLAGS="-D warnings" cargo doc "${cargo_profile_args[@]}" --locked --workspace --all-features --no-deps
    ;;
  *)
    usage
    exit 2
    ;;
esac
