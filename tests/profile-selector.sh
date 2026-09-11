#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK_DIR=$(mktemp -d)
trap 'rm -rf -- "$WORK_DIR"' EXIT

printf '%s\n' \
  '[' \
  '  {"path":"/nix/store/store-a","narSize":30},' \
  '  {"path":"/nix/store/store-b","narSize":100},' \
  '  {"path":"/not-a-store","narSize":999},' \
  '  {"path":"/nix/store/zero","narSize":0}' \
  ']' > "$WORK_DIR/path-info.json"

output=$WORK_DIR/manifest
message=$("$ROOT/scripts/select-profile-corpus" \
  --path-info "$WORK_DIR/path-info.json" \
  --output "$output" \
  --target-bytes 25 \
  --max-nar-bytes 50)

[[ "$message" == "selected 1 paths (30 bytes); excluded 0 benchmark source paths" ]]
[[ "$(<"$output")" == "/nix/store/store-a"$'\t30' ]]

if "$ROOT/scripts/select-profile-corpus" \
  --path-info "$WORK_DIR/path-info.json" \
  --output "$WORK_DIR/too-small" \
  --target-bytes 31 \
  --max-nar-bytes 50 >/dev/null 2>&1; then
  echo "expected insufficient corpus failure" >&2
  exit 1
fi

echo "profile selector tests passed"
