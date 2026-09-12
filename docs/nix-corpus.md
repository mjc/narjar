# Real-Nix corpus

`nix-corpus` is the single collection and validation command for
the real-Nix corpus. It exports uncompressed NAR streams and records both the
Nix `narHash`/`narSize` and a SHA-256 of the exact exported bytes.
It is a self-contained Bash script: `nix develop` provides its only
non-core utility, `jq`; it has no Python, Cargo, or Rust-crate dependency.
The harness prints every external command to stderr, so regeneration logs
preserve the exact build, closure, and byte-export commands.

Start from `benchmarks/corpus-spec.example.json`, replace the pinned commits,
flake attributes, and (when already materialized) generation roots, and add one
target for each permitted generation. `--build` materializes a target with
`nix build <flake_ref>#<flake_attr>` before collecting its closure. Targets may
also declare `input_overrides` when a historical flake input needs a public,
pinned replacement; the harness emits deterministic `--override-input` flags.
A target's closure is collected with `nix-store --query --requisites`; missing
roots or metadata fail the run.

```sh
scripts/nix-corpus collect \
  --spec benchmarks/corpus-spec.json \
  --manifest benchmarks/corpus-manifest.json \
  --export-dir /path/to/uncompressed-nars \
  --build

scripts/nix-corpus validate \
  --manifest benchmarks/corpus-manifest.json \
  --artifact-root /path/to/uncompressed-nars

# Expensive byte-for-byte check against the local Nix store, plus rebuild
# validation against each target's recorded NAR identity:
scripts/nix-corpus validate \
  --manifest benchmarks/corpus-manifest.json --store --rebuild
```

For a fast structural check that does not open or hash exported NAR files, use
`--schema-only`. It is mutually exclusive with `--artifact-root`, `--store`,
and `--rebuild`:

```sh
scripts/nix-corpus validate \
  --manifest benchmarks/corpus-manifest.json --schema-only
```

Pass `--spec` with `--schema-only` to verify that a manifest was collected
from the current candidate spec. The check compares the corpus id and each
target's reproducibility identity (including its pinned revision, flake
reference and attribute, machine, families, subset, and input overrides):

```sh
scripts/nix-corpus validate \
  --manifest benchmarks/corpus-manifest.json \
  --spec benchmarks/corpus-spec.json \
  --schema-only
```

The retained historical manifest intentionally does not pass this comparison
until clean regeneration replaces it; a schema-only pass without `--spec` is
not evidence that it matches the current candidate.

When present, the manifest's `targets` list must contain collected target
records with an id, generation, pinned nixpkgs revision, flake reference,
machine, family list, subset, and resolved store root. Numbered generations
are integers; workload generations may use non-empty descriptive strings.
Artifact paths and their lowercase hexadecimal SHA-256 values are either both
present or both null. Schema-only validation checks these fields without
requiring Nix or opening the artifacts.

`--rebuild` permits a rebuilt root to have a different store path name. It
compares the rebuilt root's `narHash` and `narSize` with the metadata recorded
for the target's expected root in the manifest, so historical expected roots
do not need to remain in the local store.

Keep the spec and manifest in version control; keep large NAR exports and
regeneration roots outside the repository. The manifest's `requirements` block
is intentionally enforced during validation so a partial local store cannot
silently become the headline corpus. When present, `min_generations` and
`min_nixpkgs_revisions` must be finite nonnegative integers, and
`required_families` must be a non-empty array of non-empty strings; malformed
or null requirement values fail schema validation.

`tests/nix-corpus.sh` covers the script without a real corpus: it checks a
valid exported artifact, schema-only validation through a reduced tool path
without opening an artifact, target and artifact metadata rejection, duplicate
and unknown subset paths, coverage requirements, sorted input overrides,
collection into a manifest, and byte-for-byte store rechecks through mocked Nix
commands.
