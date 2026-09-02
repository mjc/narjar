# NARJ-31 startup decision

Decision: **accept the clean-startup recovery optimization**.

The matched run used Narjar commit `c4aa453bd83452946dac9d9d28d3407bdaf5c415` and bincache commit `556a9c8f97a3c994a9de85f567a2ef16ce6513ab` on Tina, x86-64 Linux 6.18.44, a Ryzen 9 5950X in the performance governor, ZFS, Nix 2.31.5, seed 29030, and 15 measured repetitions.

## Startup results

| Paths | Narjar median / p95 / min / max | Previous Narjar median / p95 | Bincache median / p95 |
| ---: | ---: | ---: | ---: |
| 0 | 3.708 / 5.362 / 3.260 / 5.362 ms | 2.813 / 3.050 ms | 39.437 / 370.330 ms |
| 100 | 3.656 / 7.522 / 2.816 / 7.522 ms | 7.340 / 9.585 ms | 45.765 / 72.737 ms |
| 1,000 | 4.135 / 5.179 / 3.617 / 5.179 ms | 50.175 / 64.721 ms | 34.077 / 52.315 ms |
| 10,000 | 2.918 / 5.622 / 2.733 / 5.622 ms | 478.590 / 522.193 ms | 42.985 / 108.460 ms |

The 10,000-path median fell by 99.4% from the pre-change run. The result is intentionally a pathological-startup guard, not a cross-architecture performance claim; the meaningful measurement is Tina’s x86-64 Linux run.

## Correctness and recovery

The branch-added characterization test distinguishes a clean cache from one interrupted after temporary NAR creation. Clean startup skips the inventory scan; an interrupted publication leaves a durable recovery marker, causes the next startup to reconcile, and clears the marker only after recovery completes. The clean marker is bound to the trusted-key file digest, so trust-key rotation still forces reconciliation.

The benchmark confirmed 200 responses for GET and HEAD, 206 for ranges, 404 for missing paths, successful substitution with the correct key, rejection with the wrong key, invisible interrupted uploads before and after restart, and a live service plus 404 visibility after ENOSPC failure. Settled Narjar RSS remained about 2.5 MiB at 10,000 paths versus 13.7 MiB for bincache.

The operator `verify`/`reconcile` path remains the explicit full inventory check; recovery markers are treated as expected metadata by reconciliation.

## Evidence

- `environment.json`: host, toolchain, filesystem, binaries, refs, seed, and repetition count.
- `commands.txt`: exact pinned comparison build and benchmark invocation.
- `samples.jsonl`: 1,036 raw samples.
- `summary.json` and `report.md`: median, p95, minimum, and maximum for every case.
- `enospc.json`, `substitution.json`, and `recovery-operations.json`: failure, trust, and recovery evidence.
- `logs/`: complete candidate logs.
