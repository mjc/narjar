# Benchmark scripts

The measurement helpers in `scripts/` are standalone programs. The shell
benchmarks use the existing release binaries, `/proc`, core Unix tools, `jq`,
and `vmtouch`; the Rust analyzers are compiled directly with `rustc` and have
no Cargo dependencies.

Tools:

- `scripts/continuation-benchmark` for the pinned Narjar/bincache operational
  comparison, including startup, uploads, requests, recovery, ENOSPC, trust,
  and closure measurements.
- `scripts/select-profile-corpus` for selecting a byte-bounded Nix store
  corpus with `jq`.
- `scripts/nix-range-trace` for concurrent range-resume traces through a cache
  endpoint.
- `scripts/nar-report` for NAR manifest reporting and vector validation.
- `scripts/publication-lock-benchmark` for concurrent PUT latency, staging
  usage, memory, and restart recovery. Historical reports cover the
  [serialized baseline](../benchmarks/results/2026-09-11-narj70-publication-lock/report.md),
  [concurrent publication](../benchmarks/results/2026-09-12-narj110-publication/report.md),
  [ZFS](../benchmarks/results/2026-09-12-narj110-publication-zfs-enhanced/report.md),
  and [tmpfs](../benchmarks/results/2026-09-12-narj110-publication-tmpfs-enhanced/report.md).
- `scripts/casync-zfs-experiment` for a matched flat-versus-chunked storage
  experiment. It accepts two already-created, empty ZFS dataset mountpoints,
  requires matching properties, including `compression=zstd` (`zstd-3`) by
  default. Use `--compression zstd-N` for another level. Input is a directory
  of `.nar` files or `--store-root PATH`. Store-root mode queries the Nix
  closure for `narHash`/`narSize`
  metadata and streams `nix-store --dump` directly into each HTTP upload; it
  does not create a second NAR corpus on disk. Repeated NAR identities in a
  closure are recorded as path inputs but uploaded once, with their sizes
  checked for consistency. Both modes verify byte-for-byte reads, stop the
  writers, synchronize the pool, and record logical and physical counters plus
  upload/verification timings, the commands, and server logs. It never creates,
  destroys, mounts, unmounts, or changes datasets, and it refuses non-empty
  data roots.

`tests/measurement-scripts.sh` checks the streaming helpers with fake binaries
and small fixtures.
