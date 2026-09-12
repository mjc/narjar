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

jq '.targets[0].subset = "missing"' "$WORK/spec.json" > "$WORK/unknown-subset-spec.json"
if PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" collect \
  --spec "$WORK/unknown-subset-spec.json" --manifest "$WORK/unknown-subset.json" --build \
  > /dev/null 2> "$WORK/unknown-subset.err"; then
  echo "unknown corpus subset unexpectedly validated" >&2
  exit 1
fi
grep -q 'unknown subset' "$WORK/unknown-subset.err"

PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" collect \
  --spec "$WORK/spec.json" --manifest "$WORK/collected.json" --export-dir "$WORK/export" --build
jq -e '.entries | length == 1 and .[0].path == "/nix/store/mock-root" and .[0].artifact_sha256 != null' \
  "$WORK/collected.json" > /dev/null
jq '.entries[].artifact = "/no/such/corpus-artifact.nar"' \
  "$WORK/collected.json" > "$WORK/schema-only.json"
PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-only.json" --schema-only
SCHEMA_BIN="$WORK/schema-bin"
mkdir "$SCHEMA_BIN"
for command in bash env jq mktemp rm; do
  ln -s "$(command -v "$command")" "$SCHEMA_BIN/$command"
done
PATH="$SCHEMA_BIN" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-only.json" --schema-only
jq '.targets[0].generation = "workload-20260901"' "$WORK/collected.json" > "$WORK/schema-string-generation.json"
PATH="$SCHEMA_BIN" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-string-generation.json" --schema-only
jq '.targets = ["not-an-object"]' "$WORK/collected.json" > "$WORK/schema-invalid-targets.json"
if PATH="$SCHEMA_BIN" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-invalid-targets.json" --schema-only \
  > /dev/null 2> "$WORK/schema-invalid-targets.err"; then
  echo "schema-only validation accepted invalid targets" >&2
  exit 1
fi
grep -q 'targets\[0\] must be an object' "$WORK/schema-invalid-targets.err"
jq '.targets[0] |= del(.resolved_root)' "$WORK/collected.json" > "$WORK/schema-missing-target-field.json"
if PATH="$SCHEMA_BIN" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-missing-target-field.json" --schema-only \
  > /dev/null 2> "$WORK/schema-missing-target-field.err"; then
  echo "schema-only validation accepted an incomplete target" >&2
  exit 1
fi
grep -q 'targets\[0\] missing: resolved_root' "$WORK/schema-missing-target-field.err"
jq '.entries[0].artifact = null' "$WORK/schema-only.json" > "$WORK/schema-missing-artifact-path.json"
if PATH="$SCHEMA_BIN" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-missing-artifact-path.json" --schema-only \
  > /dev/null 2> "$WORK/schema-missing-artifact-path.err"; then
  echo "schema-only validation accepted incomplete artifact metadata" >&2
  exit 1
fi
grep -q 'artifact metadata must be provided together' "$WORK/schema-missing-artifact-path.err"
if PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/schema-only.json" --schema-only --store \
  > /dev/null 2> "$WORK/schema-only-conflict.err"; then
  echo "schema-only validation accepted a store check" >&2
  exit 1
fi
grep -q 'cannot be combined' "$WORK/schema-only-conflict.err"

jq '.targets[0] |= del(.resolved_root)' "$WORK/collected.json" > "$WORK/missing-resolved-root.json"
if PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/missing-resolved-root.json" --rebuild \
  > /dev/null 2> "$WORK/missing-resolved-root.err"; then
  echo "rebuild without an expected root unexpectedly validated" >&2
  exit 1
fi
grep -q 'no resolved_root' "$WORK/missing-resolved-root.err"

jq 'del(.targets)' "$WORK/collected.json" > "$WORK/missing-targets.json"
if PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/missing-targets.json" --rebuild \
  > /dev/null 2> "$WORK/missing-targets.err"; then
  echo "rebuild without targets unexpectedly validated" >&2
  exit 1
fi
grep -q 'no rebuild targets' "$WORK/missing-targets.err"

jq '.targets = ["not-an-object"]' "$WORK/collected.json" > "$WORK/invalid-targets.json"
if PATH="$MOCK_BIN:$PATH" "$ROOT/scripts/nix-corpus" validate \
  --manifest "$WORK/invalid-targets.json" --rebuild \
  > /dev/null 2> "$WORK/invalid-targets.err"; then
  echo "rebuild with invalid targets unexpectedly validated" >&2
  exit 1
fi
grep -q 'invalid rebuild targets' "$WORK/invalid-targets.err"

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
