#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
MANIFEST=$ROOT/docs/evidence/nar-vectors.json
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

command -v jq >/dev/null || { echo "jq is required; run inside nix develop" >&2; exit 1; }
REENCODER=$ROOT/target/release/nar-reencode
if [[ ! -x "$REENCODER" ]]; then
  cargo build --release --bin nar-reencode
fi

hex_file() {
  local value=$1 byte
  : > "$2"
  while [[ -n "$value" ]]; do
    byte=${value:0:2}
    printf '%b' "\\x$byte" >> "$2"
    value=${value:2}
  done
}

while IFS=$'\t' read -r name hex; do
  hex_file "$hex" "$WORK/input"
  "$REENCODER" < "$WORK/input" > "$WORK/output"
  cmp "$WORK/input" "$WORK/output"
  expected=$(jq -r --arg name "$name" '.generated_fixture_provenance.vector_sha256[$name] // empty' "$MANIFEST")
  if [[ -n "$expected" ]]; then
    actual=$(sha256sum "$WORK/input" | awk '{print $1}')
    [[ "$actual" == "$expected" ]]
  fi
done < <(jq -r '.vectors | to_entries[] | [.key,.value] | @tsv' "$MANIFEST")

base=$(jq -r '.vectors.empty_root_file' "$MANIFEST")
hex_file "$base" "$WORK/negative"
printf '%b' '\x0e\x00\x00\x00\x00\x00\x00\x00' | dd of="$WORK/negative" bs=1 seek=0 conv=notrunc status=none
if "$REENCODER" < "$WORK/negative" > /dev/null 2>&1; then exit 1; fi

hex_file "$base" "$WORK/negative"
printf '%b' '\x01' | dd of="$WORK/negative" bs=1 seek=21 conv=notrunc status=none
if "$REENCODER" < "$WORK/negative" > /dev/null 2>&1; then exit 1; fi

hex_file "$base" "$WORK/negative"
printf '%b' '\x78' | dd of="$WORK/negative" bs=1 seek=48 conv=notrunc status=none
if "$REENCODER" < "$WORK/negative" > /dev/null 2>&1; then exit 1; fi

hex_file "$base" "$WORK/negative"
truncate -s -1 "$WORK/negative"
if "$REENCODER" < "$WORK/negative" > /dev/null 2>&1; then exit 1; fi

hex_file "$base" "$WORK/negative"
printf '%b' '\x00' >> "$WORK/negative"
if "$REENCODER" < "$WORK/negative" > /dev/null 2>&1; then exit 1; fi

provenance=$(jq -r '.generated_fixture_provenance.generators[]' "$MANIFEST")
version=$(nix-store --version)
grep -Fx "$version" <<< "$provenance" >/dev/null
printf abc > "$WORK/executable"
chmod 755 "$WORK/executable"
mkdir "$WORK/empty"
ln -s x "$WORK/symlink"
for fixture in executable empty symlink; do
  store_path=$(nix-store --add "$WORK/$fixture")
  nix-store --dump "$store_path" > "$WORK/dump"
  case "$fixture" in
    executable) name=executable_root_abc ;;
    empty) name=empty_root_directory ;;
    symlink) name=root_symlink_x ;;
  esac
  hex_file "$(jq -r --arg name "$name" '.vectors[$name]' "$MANIFEST")" "$WORK/expected"
  cmp "$WORK/expected" "$WORK/dump"
done

[[ "$(jq -r '.ordering_counterexample.git_order' "$MANIFEST")" == 'a. < a/' ]]
[[ "$(jq -r '.ordering_counterexample.nar_byte_order' "$MANIFEST")" == 'a < a.' ]]
echo "NAR vector tests passed"
