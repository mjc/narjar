#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VECTORS=$ROOT/docs/evidence/semantic-descriptor-vectors.txt

[[ -r "$VECTORS" ]] || {
  printf 'missing semantic descriptor vectors: %s\n' "$VECTORS" >&2
  exit 1
}

digest_hex() {
  local escaped
  escaped=$(printf '%s' "$1" | sed 's/../\\x&/g')
  printf '%b' "$escaped" | sha256sum | awk '{print $1}'
}

count=0
while IFS='|' read -r name preimage expected; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  actual=$(digest_hex "$preimage")
  [[ "$actual" == "$expected" ]] || {
    printf '%s: expected %s, got %s\n' "$name" "$expected" "$actual" >&2
    exit 1
  }
  count=$((count + 1))
done < "$VECTORS"

[[ "$count" -ge 4 ]] || {
  printf 'expected at least 4 semantic descriptor vectors, got %s\n' "$count" >&2
  exit 1
}

printf 'semantic descriptor vectors passed (%s)\n' "$count"
