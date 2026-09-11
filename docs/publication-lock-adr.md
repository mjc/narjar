# ADR: Keep the v0.1 publication lock

- Status: Accepted
- Date: 2026-09-11
- Scope: v0.1 publication and recovery path

## Context

Narjar currently admits uploads, writes the recovery marker, streams the body,
publishes the result, and cleans up under one bounded publication worker and
lock. A throttled large upload therefore delays independent small uploads. The
lock is also the coordination boundary that makes the single recovery marker
unambiguous after interruption.

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

The small requests wait approximately one slow-upload duration regardless of
whether there are 1, 2, 8, or 32 publishers. This confirms the expected
head-of-line blocking rather than a client-side failure.

## Decision

Keep the global publication serialization for v0.1. The measured latency is a
real tradeoff, but removing the lock without a replacement recovery protocol
would make interrupted multi-publication states ambiguous. The existing
bounded queue and queue-wait metrics remain the operational interface.

## Consequences

- A slow or stalled body can delay unrelated publications.
- Queue depth and queue-wait metrics must remain visible and documented.
- Future concurrency work must define durable per-transaction recovery before
  changing admission or marker ownership.
- The benchmark is retained as a regression measurement for any redesign.

## Reconsideration gate

Reopen this decision only with a reviewed state machine for concurrent marker,
rollback, cleanup, and shutdown interleavings, plus fault-injection coverage
for each interleaving. Any replacement must preserve atomic destination
 publication and bounded admission.
