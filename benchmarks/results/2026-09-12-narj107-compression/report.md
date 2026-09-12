# NARJ-107 compression evidence

This directory promotes the raw logs from two real-Nix compression runs that
were previously retained only in temporary directories. The lanes used
`compression=none`, `compression=zstd`, and `compression=xz`, with a fresh
Narjar data directory and cache key for each encoding.

## Pilot: seven-path closure

The root NAR was 698,704 bytes. The upload wall times and root narinfo fields
were:

| Encoding | Upload wall (ms) | NarSize | FileSize |
| --- | ---: | ---: | ---: |
| none | 4,636.327 | 698,704 | 698,704 |
| zstd | 3,638.418 | 698,704 | 305,617 |
| xz | 22,038.590 | 698,704 | 237,736 |

The zstd and xz readback lanes completed `nix copy` and `nix store verify`,
and both returned HTTP 206 with 64 bytes for a range request. Their readback
wall times were 1,483.470 ms and 1,769.385 ms respectively. The raw NAR
readback was not included in the readback summary.

## Large NAR: twelve-path closure

The root NAR was 1,090,707,416 bytes. The raw result file records these values;
`server_cpu_ticks` is retained as recorded and is not presented as CPU seconds.

| Encoding | Upload wall (ms) | Server CPU ticks | Peak RSS (KiB) | Encoded logical bytes | Allocated bytes | Root FileSize |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| none | 25,155.463 | 419 | 8,008 | 1,708,941,784 | 456,106,496 | 1,090,707,416 |
| zstd | 41,028.421 | 1,780 | 16,772 | 485,858,121 | 485,759,488 | 326,614,652 |
| xz | 831,362.828 | 4,471 | 16,632 | 333,542,988 | 333,787,136 | 225,001,608 |

## Evidence boundary

These are single-run pilots, not the final policy benchmark. The recorded
binary source revision, filesystem identity, producer CPU/RSS, warmups, and
repeated distributions are missing. The large run predates the later zstd
implementation migration, so it is historical compatibility evidence rather
than a current decoder comparison. Retry, interruption, corruption, and the
full multi-corpus matrix remain open on NARJ-107.

`commands.log`, `run.log`, per-lane logs, narinfo responses, range headers, and
the machine-readable result files are retained under `pilot/` and `large/`.
