# NARJ-75 corrected flat baseline

This is the fresh current flat-cache control required before semantic-storage
candidate comparisons. It is not a semantic candidate result and does not
claim the 25% physical-byte savings gate. Candidate decisions still require
the six-category corpus and the matched raw-NAR transparent-filesystem-
compression baseline frozen by constitution version 4.

The run used Narjar commit `26577b3e8d7e996407d071acaf456cb0d0c1a401`,
pinned bincache commit `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`, Tina's
AMD Ryzen 9 5950X, the performance governor, ZFS `zroot/home`, Linux 7.2.2,
Nix 2.31.5, Rust 1.85.1, seed 29030, three warmups, and 15 measured
repetitions for repeated cases. Narjar wire compression was disabled with
`compression=none` and HTTP requests explicitly requested identity encoding.
The pinned Bincache has no no-compression serving mode and emitted `.nar.zst`,
so its numbers are retained as an operational comparator but are not a matched
no-compression baseline and cannot be consumed by constitution storage or GET
gates.
The 100 MiB and 1 GiB streaming checks each retain one measured sample after
three distinct warmup payloads; they are bounded streaming/RSS checks, not
candidate distribution evidence.

The run completed startup, RSS, GET/HEAD/Range, upload, concurrent upload,
streaming, interrupted-upload, ENOSPC, recovery, substitution/trust, closure,
and command-log phases. `samples.jsonl` contains 1,036 raw samples and
`summary.json`/`report.md` contain their aggregate distributions. HTTP checks
returned 200 for GET/HEAD, 206 for Range, and 404 for missing or interrupted
objects. Both services survived ENOSPC without publishing the failed object,
restarted with it still absent, rejected an unrelated signing key, and
substituted with the configured key.

Selected current flat-control medians (Bincache is unmatched as noted above):

| Case | Narjar | Bincache |
| --- | ---: | ---: |
| startup, 10,000 paths | 51.276 ms | 26.552 ms |
| settled idle RSS, 10,000 paths | 3,072 KiB | 18,440 KiB |
| warm full GET throughput | 391.402 MiB/s | 1,982.513 MiB/s |
| warm Range latency | 49.737 ms | 0.214 ms |
| 1 GiB streaming upload wall | 7,591.933 ms | 7,981.504 ms |
| runtime closure | 45,076,512 bytes | 51,956,840 bytes |

`environment.json` records the exact binaries and hashes. `commands.txt` was
written by the subprocess and HTTP wrappers during execution and records the
actual commands, URLs, methods, non-secret headers, and identity encoding.
Generated bearer-token values are intentionally absent. Failure, recovery,
trust, raw-sample, aggregate, and candidate-log evidence is retained beside
this file.
