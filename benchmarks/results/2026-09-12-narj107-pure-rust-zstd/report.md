# Pure-Rust zstd decoder comparison

This compares the three pure-Rust streaming decoders under consideration for
NARJ-107. It uses the same decoder loop and the same compressed NAR inputs for
each candidate. Input loading is outside the timed region; the sink counts
decoded bytes, so destination filesystem latency is not part of this codec
comparison.

## Result

`structured-zstd` is the fastest candidate in this comparison. Its native build
selected the AVX2 kernel on the benchmark host.

| Candidate | Medium median | Large median | Medium range | Large range |
| --- | ---: | ---: | ---: | ---: |
| `structured-zstd` 0.0.52 | 1,284.96 MiB/s | 703.08 MiB/s | 1,281.87–1,305.07 | 689.39–716.77 |
| `zstd-complete` 0.2.0 | 602.45 MiB/s | 314.96 MiB/s | 411.34–626.51 | 311.09–318.82 |
| `ruzstd` 0.8.2 | 382.57 MiB/s | 295.62 MiB/s | 252.77–506.42 | 264.36–326.88 |

The benchmark host was busy (load average was 42.17 at the start of the
native pass), so these are comparative throughput results rather than a clean
absolute capacity claim. All candidates ran sequentially, were pinned to CPU
0, and used the same host and input. The ordering is still decisive: the
structured decoder's median was 2.13x `zstd-complete` on the medium input and
2.23x on the large input.

## Setup validation

- `ruzstd` used its default `hash` and `std` features explicitly; it has no
  SIMD feature set.
- `zstd-complete` used its default `hash` and `std` features explicitly; its
  BMI2 paths remain runtime-selected and its SIMD code is compile-target
  dependent.
- `structured-zstd` was built with all relevant x86 runtime kernels enabled:
  `kernel-sse`, `kernel-bmi2`, and `kernel-avx2` (the feature implication chain
  supplies the lower tiers). Its exact crate defaults were also built once as
  a sanity check; they selected AVX2 and produced the same output.
- Every native build used `RUSTFLAGS='-C target-cpu=native'`.
- The harness warmed each decoder once, timed only repeated streaming decode,
  used a 64 KiB output buffer, and verified each candidate byte-for-byte
  against the small uncompressed source before timing. The medium and large
  timing runs checked the expected decoded byte count on every iteration.

This does not benchmark encoding or the eventual egress path. No dependency
switch is included in this result; the next implementation step is to trial
`structured-zstd` in Narjar, bump the declared MSRV to 1.92, and run the full
compatibility and project gates.
