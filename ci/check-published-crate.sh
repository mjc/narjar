#!/usr/bin/env bash
set -euo pipefail

user_agent='narjar-release (https://github.com/mjc/narjar)'
status=$(curl --location --silent --show-error --retry 5 --user-agent "$user_agent" \
  --output target/registry-state.json --write-out '%{http_code}' \
  "https://crates.io/api/v1/crates/narjar/$RELEASE_VERSION")
case "$status" in
  200)
    jq -e --arg version "$RELEASE_VERSION" \
      '.version.crate == "narjar" and .version.num == $version' target/registry-state.json >/dev/null
    curl --fail --location --silent --show-error --retry 5 --user-agent "$user_agent" \
      --output target/registry.crate \
      "https://static.crates.io/crates/narjar/narjar-$RELEASE_VERSION.crate"
    cmp target/registry.crate "target/release/narjar-$RELEASE_VERSION.crate"
    printf 'published=true\n' >> "$GITHUB_OUTPUT"
    ;;
  404) printf 'published=false\n' >> "$GITHUB_OUTPUT" ;;
  *)
    printf 'Could not determine registry publication status: HTTP %s\n' "$status" >&2
    exit 1
    ;;
esac
