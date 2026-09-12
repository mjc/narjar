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

`--rebuild` permits a rebuilt root to have a different store path name. It
compares the rebuilt root's `narHash` and `narSize` with the metadata recorded
for the target's expected root in the manifest, so historical expected roots
do not need to remain in the local store.

Keep the spec and manifest in version control; keep large NAR exports and
regeneration roots outside the repository. The manifest's `requirements` block
is intentionally enforced during validation so a partial local store cannot
silently become the headline corpus.

`tests/nix-corpus.sh` covers the script without a real corpus: it checks a
valid exported artifact, schema-only validation without opening an artifact,
rejection of duplicate and unknown subset paths, coverage requirements, sorted
input overrides, collection into a manifest, and byte-for-byte store rechecks
through mocked Nix commands.
