#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

printf '%s\n' '#!/usr/bin/env bash' 'sleep 0.02' 'printf "raw_size=%s sha256=fake\\n" "$1"' > "$WORK/encoder"
printf '%s\n' '#!/usr/bin/env bash' 'while IFS= read -r path; do cat "$path" >/dev/null; done < "$2"' > "$WORK/scanner"
printf '%s\n' '#!/usr/bin/env bash' 'cat' > "$WORK/reencoder"
chmod +x "$WORK/encoder" "$WORK/scanner" "$WORK/reencoder"

"$ROOT/scripts/nar-encode-memory" \
  --encoder "$WORK/encoder" --output "$WORK/encode.json" --size 1KiB
jq -e '.cases[0].size_bytes == 1024 and .cases[0].sha256 == "fake"' \
  "$WORK/encode.json" > /dev/null

"$ROOT/scripts/nar-memory" \
  --scanner "$WORK/scanner" --output "$WORK/memory.json" --size 1KiB
jq -e '.results[0].size_bytes == 1024 and .generated_zero_stream == true' \
  "$WORK/memory.json" > /dev/null

printf 'round-trip bytes' > "$WORK/example.nar"
"$ROOT/scripts/nar-roundtrip" \
  --root "$WORK" --reencoder "$WORK/reencoder" --output "$WORK/roundtrip.json"
jq -e '.nar_count == 1 and .equal_count == 1 and .mismatch_count == 0' \
  "$WORK/roundtrip.json" > /dev/null
