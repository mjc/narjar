#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

jq -n --slurpfile constitution "$ROOT/benchmarks/constitution.json" '
  {
    provenance: (reduce $constitution[0].provenance_required_fields[] as $field ({}; .[$field] = "present")),
    metric: (reduce $constitution[0].metric_required_fields[] as $field ({}; .[$field] = 50))
  }
' > "$WORK/valid.json"
[[ "$($ROOT/scripts/evaluate-constitution "$WORK/valid.json")" == strong ]]

for value_and_result in '24.999 reject' '25 conditional' '50 strong'; do
  read -r value result <<< "$value_and_result"
  jq --argjson value "$value" '.metric.savings_percent = $value' "$WORK/valid.json" > "$WORK/case.json"
  [[ "$($ROOT/scripts/evaluate-constitution "$WORK/case.json")" == "$result" ]]
done

jq 'del(.provenance.commit)' "$WORK/valid.json" > "$WORK/missing.json"
if "$ROOT/scripts/evaluate-constitution" "$WORK/missing.json" > /dev/null 2> "$WORK/missing.err"; then
  echo "incomplete constitution record unexpectedly passed" >&2
  exit 1
fi
grep -q 'commit' "$WORK/missing.err"
