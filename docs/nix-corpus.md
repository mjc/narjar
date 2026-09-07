# Real-Nix corpus

`benchmarks/nix_corpus.py` is the single collection and validation command for
the real-Nix corpus. It exports uncompressed NAR streams and records both the
Nix `narHash`/`narSize` and a SHA-256 of the exact exported bytes.

Start from `benchmarks/corpus-spec.example.json`, replace the pinned commits,
flake attributes, and (when already materialized) generation roots, and add one
target for each permitted generation. `--build` materializes a target with
`nix build <flake_ref>#<flake_attr>` before collecting its closure. A target's
closure is collected with `nix-store --query --requisites`; missing roots or
metadata fail the run.

```sh
python benchmarks/nix_corpus.py collect \
  --spec benchmarks/corpus-spec.json \
  --manifest benchmarks/corpus-manifest.json \
  --export-dir /path/to/uncompressed-nars \
  --build

python benchmarks/nix_corpus.py validate \
  --manifest benchmarks/corpus-manifest.json \
  --artifact-root /path/to/uncompressed-nars

# Expensive byte-for-byte check against the local Nix store:
python benchmarks/nix_corpus.py validate \
  --manifest benchmarks/corpus-manifest.json --store --rebuild
```

Keep the spec and manifest in version control; keep large NAR exports and
regeneration roots outside the repository. The manifest's `requirements` block
is intentionally enforced during validation so a partial local store cannot
silently become the headline corpus.
