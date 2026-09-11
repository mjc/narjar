#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

printf 'prefixsamepayloadsuffix' > "$WORK/first.nar"
printf 'other--samepayloadsuffix' > "$WORK/second.nar"
first_size=$(wc -c < "$WORK/first.nar" | tr -d '[:space:]')
second_size=$(wc -c < "$WORK/second.nar" | tr -d '[:space:]')

printf '%s\n' '# narjar-nar-scan-v1' > "$WORK/scan.tsv"
printf 'O\t%s\tfile\t12\tsame\t6\t0\t\n' "$WORK/first.nar" >> "$WORK/scan.tsv"
printf 'O\t%s\tfile\t12\tsame\t7\t0\t\n' "$WORK/second.nar" >> "$WORK/scan.tsv"
printf 'N\t%s\t%s\tfirst\tdirectory\t1\t1\t0\n' "$WORK/first.nar" "$first_size" >> "$WORK/scan.tsv"
printf 'N\t%s\t%s\tsecond\tdirectory\t1\t1\t0\n' "$WORK/second.nar" "$second_size" >> "$WORK/scan.tsv"

jq -n --arg first "$WORK/first.nar" --arg second "$WORK/second.nar" '
  {
    schema_version: 1,
    entries: [
      {artifact: $first, nar_size: 23, targets: ["a"], machines: ["m"], families: ["f"], generations: ["1"], nixpkgs_revisions: ["r"], subset: "core"},
      {artifact: $second, nar_size: 24, targets: ["b"], machines: ["m"], families: ["f"], generations: ["2"], nixpkgs_revisions: ["r"], subset: "core"}
    ]
  }
' > "$WORK/manifest.json"

"$ROOT/scripts/nar-report" \
  --manifest "$WORK/manifest.json" \
  --scan "$WORK/scan.tsv" \
  --output "$WORK/report"

jq -e '
  .objects.duplicate_payload_bytes == 12
  and .objects.collision_count == 0
  and .nar.artifact_occurrences == 2
  and .slices.targets.a.artifact_files == 1
  and .slices.subsets.core.artifact_files == 2
  and .whole_nar_deduplication.already_whole_nar_deduplicated_bytes == 0
' "$WORK/report/report.json" > /dev/null
