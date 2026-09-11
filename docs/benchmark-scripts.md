# Benchmark scripts

The measurement helpers in `scripts/` are standalone programs. The shell
benchmarks use the existing release binaries, `/proc`, core Unix tools, `jq`,
and `vmtouch`; the Rust analyzers are compiled directly with `rustc` and have
no Cargo dependencies.

The active helpers are:

- `scripts/continuation-benchmark` for the pinned Narjar/bincache operational
  comparison, including startup, uploads, requests, recovery, ENOSPC, trust,
  and closure measurements.
- `scripts/select-profile-corpus` for selecting a byte-bounded Nix store
  corpus with `jq`.
- `scripts/nix-range-trace` for concurrent range-resume traces through a cache
  endpoint.
- `scripts/nar-report` for NAR manifest reporting and vector validation.

`tests/measurement-scripts.sh` continues to exercise the older streaming
helpers with small fake binaries; it does not require a large corpus.
