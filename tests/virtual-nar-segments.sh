#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MAP=$ROOT/docs/evidence/virtual-nar-segments.tsv

[[ -r "$MAP" ]] || {
  printf 'missing virtual segment map: %s\n' "$MAP" >&2
  exit 1
}

awk -F '\t' '
  $0 ~ /^#/ || NF == 0 { next }
  NF != 5 { printf "bad segment row %d\n", NR > "/dev/stderr"; exit 1 }
  {
    fixture=$1; offset=$2 + 0; segment_length=$3 + 0; kind=$4; source=$5
    if (!(fixture in next_offset)) next_offset[fixture] = 0
    if (offset != next_offset[fixture]) {
      printf "%s: expected offset %d, got %d\n", fixture, next_offset[fixture], offset > "/dev/stderr"
      exit 1
    }
    if (segment_length <= 0 || (kind != "literal" && kind != "extent")) {
      printf "%s: invalid segment at row %d\n", fixture, NR > "/dev/stderr"
      exit 1
    }
    next_offset[fixture] = offset + segment_length
    count[fixture]++
  }
  END {
    if (next_offset["root_symlink_x"] != 120) {
      printf "root_symlink_x: expected 120 bytes, got %d\n", next_offset["root_symlink_x"] > "/dev/stderr"
      exit 1
    }
    if (count["root_symlink_x"] != 9) {
      printf "root_symlink_x: expected 9 segments, got %d\n", count["root_symlink_x"] > "/dev/stderr"
      exit 1
    }
  }
' "$MAP"

printf 'virtual NAR segment map passed\n'
