#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

REPORTER=$ROOT/target/debug/nar-tree-report
[[ -x "$REPORTER" ]] || {
  printf 'missing %s; build --bin nar-tree-report first\n' "$REPORTER" >&2
  exit 1
}
command -v nix-store >/dev/null || {
  printf 'nix-store is required; run inside nix develop\n' >&2
  exit 1
}

mkdir -p "$WORK/root/a" "$WORK/root/b"
printf x > "$WORK/root/a/child"
cp "$WORK/root/a/child" "$WORK/root/b/child"
store_path=$(nix-store --add "$WORK/root")
nix-store --dump "$store_path" > "$WORK/root.nar"
printf '%s\n' "$WORK/root.nar" > "$WORK/paths"

"$REPORTER" --input-list "$WORK/paths" --output "$WORK/report.tsv"
row=$(awk -F '\t' '$1 == "N" { print; exit }' "$WORK/report.tsv")
[[ -n "$row" ]] || { printf 'missing N row\n' >&2; exit 1; }
IFS=$'\t' read -r kind path entries trees unique repeated bytes depth fanout <<< "$row"
[[ "$kind" == N && "$entries" == 4 ]] || { printf 'unexpected entry count: %s\n' "$row" >&2; exit 1; }
[[ "$trees" == 3 && "$unique" == 2 && "$repeated" == 1 ]] || {
  printf 'unexpected tree sharing: %s\n' "$row" >&2
  exit 1
}

printf 'NAR tree report test passed\n'
