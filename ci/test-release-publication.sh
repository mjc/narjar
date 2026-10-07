#!/usr/bin/env bash
set -euo pipefail

repository_root=$PWD
mkdir -p target/release-tests/target/release
cd target/release-tests
export GITHUB_REPOSITORY=mjc/narjar RELEASE_TAG=v0.1.0 RELEASE_VERSION=0.1.0
export GITHUB_OUTPUT=$PWD/target/output
printf 'crate bytes\n' > target/release/narjar-0.1.0.crate
printf 'binary bytes\n' > target/release/narjar-v0.1.0-x86_64-linux.tar.gz
printf 'checksums\n' > target/release/SHA256SUMS
printf 'notes\n' > target/release/release-notes.md

curl() {
  if [[ "${!#}" == https://static.crates.io/* ]]; then
    case "$scenario" in
      registry-identical) cp target/release/narjar-0.1.0.crate target/registry.crate ;;
      registry-mismatch) printf 'different bytes\n' > target/registry.crate ;;
      registry-download-error) return 22 ;;
      *) printf 'Unexpected registry download: %s\n' "$scenario" >&2; return 1 ;;
    esac
    return
  fi
  case "$scenario" in
    registry-missing) printf 404 ;;
    registry-unavailable) printf 503 ;;
    registry-network-error) return 7 ;;
    registry-mismatch|registry-identical|registry-download-error)
      printf '{"version":{"crate":"narjar","num":"0.1.0"}}\n' > target/registry-state.json
      printf 200
      ;;
    registry-wrong-version)
      printf '{"version":{"crate":"narjar","num":"0.0.0"}}\n' > target/registry-state.json
      printf 200
      ;;
    *) printf 'Unexpected curl scenario: %s\n' "$scenario" >&2; return 1 ;;
  esac
}
export -f curl

for scenario in registry-missing registry-identical; do
  export scenario
  : > "$GITHUB_OUTPUT"
  bash "$repository_root/ci/check-published-crate.sh"
  expected=false
  [[ "$scenario" != registry-identical ]] || expected=true
  grep -Fxq "published=$expected" "$GITHUB_OUTPUT"
done
for scenario in registry-unavailable registry-network-error registry-mismatch registry-download-error registry-wrong-version; do
  export scenario
  : > "$GITHUB_OUTPUT"
  if output=$(bash "$repository_root/ci/check-published-crate.sh" 2>&1); then
    printf 'Registry state unexpectedly accepted: %s\n%s\n' "$scenario" "$output" >&2
    exit 1
  fi
  test ! -s "$GITHUB_OUTPUT"
done

gh() {
  printf '%s\n' "$*" >> target/calls
  if [[ "$1" == api ]]; then
    local endpoint=${!#}
    if [[ "$endpoint" == */releases?per_page=100 ]]; then
      case "$scenario" in
        github-unavailable) printf '{"status":"503"}\n'; return 1 ;;
        github-missing|github-create-failure)
          # Creating a draft does not guarantee immediate visibility in the list API.
          printf '[[]]\n'
          return
          ;;
      esac
      printf '[[{"id":42,"tag_name":"v0.1.0"},{"id":43,"tag_name":"v0.0.0"}]]\n'
      return
    fi
    if [[ "$endpoint" != */releases/42 ]]; then
      printf 'Unexpected release endpoint: %s\n' "$endpoint" >&2
      return 1
    fi
    case "$scenario" in
      github-missing|github-draft|github-upload-failure) printf '{"draft":true}\n' ;;
      github-public|github-mismatch) printf '{"draft":false}\n' ;;
      github-invalid-state) printf '{}\n' ;;
      *) printf 'Unexpected GitHub scenario: %s\n' "$scenario" >&2; return 1 ;;
    esac
    return
  fi
  case "$2" in
    create)
      [[ "$scenario" != github-create-failure ]] || return 1
      touch target/created
      ;;
    upload) [[ "$scenario" != github-upload-failure ]] ;;
    edit) ;;
    download)
      local asset=$5
      cp "target/release/$asset" "target/github-release/$asset"
      [[ "$scenario" != github-mismatch ]] || printf 'different bytes\n' > "target/github-release/$asset"
      ;;
    *) printf 'Unexpected gh call: %s\n' "$*" >&2; return 1 ;;
  esac
}
export -f gh

require_no_release_mutation() {
  if grep -Eq 'release (create|upload|edit)' target/calls; then
    printf 'Unexpected mutation of an existing release or failed lookup:\n' >&2
    cat target/calls >&2
    exit 1
  fi
}

for scenario in github-missing github-draft github-public; do
  export scenario
  : > target/calls
  rm -f target/created
  bash "$repository_root/ci/publish-github-release.sh"
  case "$scenario" in
    github-missing)
      grep -Fq 'release create v0.1.0 target/release/narjar-0.1.0.crate target/release/narjar-v0.1.0-x86_64-linux.tar.gz target/release/SHA256SUMS --verify-tag' target/calls
      test "$(grep -c 'releases?per_page=100' target/calls)" -eq 1
      if grep -Eq 'release (upload|edit)|--draft' target/calls; then exit 1; fi
      ;;
    github-draft)
      grep -Fq 'release upload v0.1.0' target/calls
      grep -Fq -- '--clobber' target/calls
      if grep -Fq 'release create' target/calls; then exit 1; fi
      ;;
    github-public)
      test "$(grep -c 'release download' target/calls)" -eq 3
      require_no_release_mutation
      ;;
  esac
done
for scenario in github-unavailable github-mismatch github-invalid-state; do
  export scenario
  : > target/calls
  if output=$(bash "$repository_root/ci/publish-github-release.sh" 2>&1); then
    printf 'GitHub state unexpectedly accepted: %s\n%s\n' "$scenario" "$output" >&2
    exit 1
  fi
  require_no_release_mutation
done

for scenario in github-create-failure github-upload-failure; do
  export scenario
  : > target/calls
  if bash "$repository_root/ci/publish-github-release.sh"; then
    printf 'Asset publication failure unexpectedly accepted: %s\n' "$scenario" >&2
    exit 1
  fi
  if grep -Fq 'release edit' target/calls; then
    printf 'Published a release after asset publication failed: %s\n' "$scenario" >&2
    exit 1
  fi
done

printf 'Publication retries compare registry bytes and never overwrite published GitHub assets.\n'
