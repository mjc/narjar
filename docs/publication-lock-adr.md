# ADR: Publication serialization and per-publication recovery

- Status: Superseded by NARJ-110
- Original date: 2026-09-11
- Superseded: 2026-09-12
- Scope: v0.1 publication and recovery path

## Context

The original v0.1 design admitted uploads, wrote the recovery marker, streamed
the body, published the result, and cleaned up under one bounded publication
worker and global lock. A throttled large upload therefore delayed independent
small uploads. The lock was also the coordination boundary that made the
single recovery marker unambiguous after interruption.

## Evidence

The reproducible harness is
[`scripts/publication-lock-benchmark`](../scripts/publication-lock-benchmark),
with its interface check in
[`tests/publication-lock-benchmark.sh`](../tests/publication-lock-benchmark.sh).
The full raw output is in
[`benchmarks/results/2026-09-11-narj70-publication-lock`](../benchmarks/results/2026-09-11-narj70-publication-lock).

It was run from commit `5fbd212c6474a0b3d67ec846a1d7eb616ce5def0` with the
release Nix binary:

```text
nix develop -c bash scripts/publication-lock-benchmark \
  --narjar-bin /nix/store/7iydfr0xlpvq73yqgpwl323kiik3x28b-narjar-0.1.0/bin/narjar \
  --output benchmarks/results/2026-09-11-narj70-publication-lock
```

The run used a raw 1 GiB PUT throttled to 64 MiB/s and 32 HTTP workers. The
publication worker remained serialized. The storage path was ZFS
(`zroot/home`, mounted with `rw,relatime,xattr,noacl,casesensitive`). Every
upload returned 2xx, and the command log records the exact upload commands.

| Small publishers | Small PUT p50 | p95 | p99 | Slow throughput | Peak RSS | Queue waits |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 16.083 s | 16.083 s | 16.083 s | 57.655 MiB/s | 7,112 KiB | 2 |
| 2 | 16.601 s | 16.617 s | 16.617 s | 57.613 MiB/s | 7,156 KiB | 3 |
| 8 | 16.292 s | 16.346 s | 16.346 s | 57.548 MiB/s | 7,340 KiB | 9 |
| 32 | 16.331 s | 16.614 s | 16.643 s | 57.647 MiB/s | 7,908 KiB | 33 |

The small requests waited approximately one slow-upload duration regardless of
whether there were 1, 2, 8, or 32 publishers. This confirmed the expected
head-of-line blocking rather than a client-side failure.

## Original decision

Keep the global publication serialization for v0.1 until a replacement recovery
protocol exists. The measured latency was a real tradeoff, and removing the
lock without replacement would have made interrupted multi-publication states
ambiguous.

## Current decision

NARJ-110 replaced the global lock with one durable transaction record per
publication. Records are created and synced in `staging` before body
streaming, then advance through `streaming`, `validated`, `linked`, and
`published`; they are removed only after temporary cleanup and the final
durable state. Independent publications use bounded worker and admission
queues. Only final-link comparison and the destination-directory sync use a
narrow lock for the same destination. Startup enumerates every transaction
record, validates its state and the published inventory, and only then clears
recovery state.

The current implementation and measurements are documented in
[`architecture.md`](architecture.md), [`operations.md`](operations.md), and
[`NARJ-110 publication results`](../benchmarks/results/2026-09-12-narj110-publication/report.md).
The enhanced harness also records post-load RSS, anonymous allocator memory,
staging usage, and restart recovery in the
[`ZFS results`](../benchmarks/results/2026-09-12-narj110-publication-zfs-enhanced/report.md)
and [`tmpfs results`](../benchmarks/results/2026-09-12-narj110-publication-tmpfs-enhanced/report.md).
For a measured baseline, run the same command with `--repetitions 15`; each
repetition uses an independent data directory and is retained in the raw TSV
outputs.

## Consequences

- A slow or stalled body no longer holds a process-wide publication lock.
- Queue depth and queue-wait metrics must remain visible and documented.
- Per-destination commit serialization remains necessary for same-target
  immutable publication races.
- Recovery records and startup inventory validation are required before clearing
  the recovery gate.
- The benchmark is retained as a regression measurement for any redesign.

## Reconsideration gate

Reopen this decision if the transaction protocol, bounded admission, or
per-destination commit semantics change. Any replacement must preserve atomic
destination publication, bounded admission, startup recovery, and the
NAR-before-narinfo visibility invariant.
