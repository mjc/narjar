#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
help=$("$ROOT/scripts/continuation-benchmark" --help)
[[ "$help" == *"--bincache-bin"* ]]
[[ "$help" == *"--repetitions"* ]]
[[ "$help" == *"--quick"* ]]

if NARJAR_BIN=/does/not/exist "$ROOT/scripts/continuation-benchmark" \
  --output "$(mktemp -d)/output" >/dev/null 2>&1; then
  echo "expected missing binary failure" >&2
  exit 1
fi

echo "continuation benchmark interface tests passed"
