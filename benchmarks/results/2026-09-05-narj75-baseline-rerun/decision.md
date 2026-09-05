# NARJ-75 flat-baseline rerun

This is the fresh current flat-cache baseline required before semantic-storage
candidate comparisons. It is not a semantic candidate result and does not
claim the 25% physical-byte savings gate; the matched raw-NAR transparent
filesystem-compression baseline remains the later comparison defined by the
frozen constitution.

The run used Narjar commit `655b9cd1ffba40de97ed22fb28319ac14e7d3baa`, pinned
bincache commit `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`, Tina's AMD Ryzen 9
5950X, performance governor, ZFS `zroot/home`, Linux 7.2.2, Nix 2.31.5,
Rust 1.85.1, seed 29030, three warmups, and 15 measured repetitions. Wire
compression was disabled with `compression=none`. The 10,000-root corpus is
the benchmark's cardinality corpus; its file payload is 38,890 bytes.

The run completed all startup, RSS, GET/HEAD/Range, upload, concurrent upload,
streaming, interrupted-upload, ENOSPC, recovery, substitution/trust, closure,
and command-log phases. `samples.jsonl` contains 1,036 raw samples and
`summary.json`/`report.md` contain the aggregate distributions. HTTP checks
returned 200 for GET/HEAD, 206 for Range, 404 for missing/interrupted objects;
both services survived ENOSPC and rejected the wrong signing key.

Selected current flat-baseline medians:

| Case | Narjar | Bincache |
| --- | ---: | ---: |
| startup, 10,000 paths | 51.298 ms | 28.705 ms |
| settled idle RSS, 10,000 paths | 2,524 KiB | 17,652 KiB |
| warm full GET throughput | 397.108 MiB/s | 1,884.872 MiB/s |
| warm Range latency | 49.843 ms | 0.267 ms |
| 1 GiB streaming upload wall | 7,225.849 ms | 6,844.927 ms |
| runtime closure | 45,076,512 bytes | 51,956,840 bytes |

The exact command, environment, raw samples, aggregate report, failure and
trust records, and candidate logs are retained beside this file.
