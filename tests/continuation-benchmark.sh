#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
help=$("$ROOT/scripts/continuation-benchmark" --help)
[[ "$help" == *"--bincache-bin"* ]]
[[ "$help" == *"--repetitions"* ]]
[[ "$help" == *"--quick"* ]]
rg -q 'candidate_listen' "$ROOT/scripts/continuation-benchmark"
rg -q 'BINCACHE_PORT' "$ROOT/scripts/continuation-benchmark"
rg -q 'BENCHMARK_WORKERS=32' "$ROOT/scripts/continuation-benchmark"
rg -q "size_download}\\\\n'" "$ROOT/scripts/continuation-benchmark"
rg -q 'method" == HEAD' "$ROOT/scripts/continuation-benchmark"
rg -q 'set -- "\$@" -I' "$ROOT/scripts/continuation-benchmark"

if NARJAR_BIN=/does/not/exist "$ROOT/scripts/continuation-benchmark" \
  --output "$(mktemp -d)/output" >/dev/null 2>&1; then
  echo "expected missing binary failure" >&2
  exit 1
fi

echo "continuation benchmark interface tests passed"
