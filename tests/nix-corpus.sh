#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT

printf nar > "$WORK/example.nar"
NAR_HASH=$(nix hash file --type sha256 --sri "$WORK/example.nar")
NAR_SHA256=$(sha256sum "$WORK/example.nar" | cut -d ' ' -f 1)

jq -n \
  --arg nar_hash "$NAR_HASH" \
  --arg artifact_sha256 "$NAR_SHA256" \
  --arg artifact "$WORK/example.nar" \
  '{
    schema_version: 1,
    requirements: {},
    subsets: {core: {entries: ["/nix/store/example"]}},
    entries: [{
      path: "/nix/store/example",
      nar_hash: $nar_hash,
      nar_size: 3,
      artifact_sha256: $artifact_sha256,
      artifact: $artifact,
      targets: ["generation-1"],
      machines: ["default-nixos"],
      families: ["nixos"],
      generations: ["1"],
      nixpkgs_revisions: ["abc"],
      flake_refs: ["flake"],
      derivations: []
    }]
  }' > "$WORK/manifest.json"

"$ROOT/scripts/nix-corpus" validate --manifest "$WORK/manifest.json"

jq '.entries += [.entries[0]] | .subsets.core.entries += ["/nix/store/missing"]' \
  "$WORK/manifest.json" > "$WORK/duplicate.json"
if "$ROOT/scripts/nix-corpus" validate --manifest "$WORK/duplicate.json" > /dev/null 2> "$WORK/duplicate.err"; then
  echo "duplicate manifest unexpectedly validated" >&2
  exit 1
fi
grep -q 'duplicate path' "$WORK/duplicate.err"
grep -q 'references unknown paths' "$WORK/duplicate.err"

jq '.requirements = {min_generations: 2, min_nixpkgs_revisions: 2}' \
  "$WORK/manifest.json" > "$WORK/coverage.json"
if "$ROOT/scripts/nix-corpus" validate --manifest "$WORK/coverage.json" > /dev/null 2> "$WORK/coverage.err"; then
  echo "under-covered manifest unexpectedly validated" >&2
  exit 1
fi
grep -q 'generations' "$WORK/coverage.err"
grep -q 'nixpkgs revisions' "$WORK/coverage.err"

MOCK_BIN="$WORK/mock-bin"
mkdir "$MOCK_BIN"
export NIX_CORPUS_TEST_LOG="$WORK/nix.log"
export NAR_HASH
export REAL_NIX="$(command -v nix)"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  'printf "%q " "$@" >> "$NIX_CORPUS_TEST_LOG"' \
  'printf "\n" >> "$NIX_CORPUS_TEST_LOG"' \
  'case "$1" in' \
  '  build) printf "%s\n" /nix/store/mock-root ;;' \
  '  path-info) if [[ "$3" == /nix/store/expected-root ]]; then exit 1; elif [[ "${NIX_CORPUS_TEST_MISMATCH:-}" == 1 ]]; then printf "[{\"path\":\"%s\",\"narHash\":\"sha256-different\",\"narSize\":3,\"deriver\":\"/nix/store/mock.drv\"}]\n" "$3"; else printf "[{\"path\":\"%s\",\"narHash\":\"%s\",\"narSize\":3,\"deriver\":\"/nix/store/mock.drv\"}]\n" "$3" "$NAR_HASH"; fi ;;' \
  '  hash) exec "$REAL_NIX" "$@" ;;' \
  '  *) exit 1 ;;' \
  'esac' > "$MOCK_BIN/nix"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -Eeuo pipefail' \
  'if [[ "$1" == "--query" ]]; then printf "%s\n" /nix/store/mock-root; else printf nar; fi' > "$MOCK_BIN/nix-store"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "$1"' > "$MOCK_BIN/realpath"
chmod +x "$MOCK_BIN/nix" "$MOCK_BIN/nix-store" "$MOCK_BIN/realpath"

jq -n '{
  schema_version: 1,
  corpus_id: "test",
  source: {},
  requirements: {},
  subsets: {core: {weight: 1}},
  targets: [{
    id: "generation-1",
    generation: 1,
    nixpkgs_revision: "abc",
    flake_ref: "flake",
    flake_attr: "nixosConfigurations.generation",
    machine: "default-nixos",
    families: ["nixos"],
    subset: "core",
    input_overrides: {"z-input": "z-ref", "a-input": "a-ref"}
  }]
}' > "$WORK/spec.json"
PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" collect \
  --spec "$WORK/spec.json" --manifest "$WORK/collected.json" --export-dir "$WORK/export" --build
jq -e '.entries | length == 1 and .[0].path == "/nix/store/mock-root" and .[0].artifact_sha256 != null' \
  "$WORK/collected.json" > /dev/null
jq '.entries += [(.entries[0] | .path = "/nix/store/expected-root")] |
  .targets[0].resolved_root = "/nix/store/expected-root" |
  del(.coverage)' \
  "$WORK/collected.json" > "$WORK/rebuild.json"
PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/rebuild.json" --rebuild
if NIX_CORPUS_TEST_MISMATCH=1 PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/rebuild.json" --rebuild > /dev/null 2> "$WORK/rebuild.err"; then
  echo "mismatched rebuild unexpectedly validated" >&2
  exit 1
fi
grep -q 'rebuilt content differs' "$WORK/rebuild.err"
PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate --manifest "$WORK/collected.json" --store
grep -q 'build --no-link --print-out-paths --override-input a-input a-ref --override-input z-input z-ref flake#nixosConfigurations.generation' "$NIX_CORPUS_TEST_LOG"
