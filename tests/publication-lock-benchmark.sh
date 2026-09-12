#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPT=$ROOT/scripts/publication-lock-benchmark
TEMP_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEMP_DIR"' EXIT

help=$(bash "$SCRIPT" --help)
[[ "$help" == *"--narjar-bin"* ]]
[[ "$help" == *"--output"* ]]
[[ "$help" == *"--slow-bytes"* ]]
[[ "$help" == *"--slow-rate"* ]]
[[ "$help" == *"--publishers"* ]]
[[ "$help" == *"throughput"* ]]
[[ "$help" == *"post-load RSS"* ]]
[[ "$help" == *"staging usage"* ]]
[[ "$help" == *"restart recovery time"* ]]
[[ "$help" == *"anonymous allocator memory"* ]]

if bash "$SCRIPT" --output "$TEMP_DIR/output" --narjar-bin /does/not/exist >/dev/null 2>&1; then
  echo "expected missing binary failure" >&2
  exit 1
fi

echo "publication lock benchmark interface tests passed"
