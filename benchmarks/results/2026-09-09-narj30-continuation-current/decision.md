# NARJ-30 current flat baseline

This is the corrected current-state continuation run against the pinned
Bincache reference. It used three warmups, 15 measured repetitions, the
10,000-path corpus, identity HTTP encoding, and `compression=none` for both
candidates. `commands.txt` contains the commands and requests executed;
`samples.jsonl` contains the raw measurements.

Narjar completed the full benchmark successfully. `samples.jsonl` contains
1,336 raw samples. The important medians are:

| Case | Narjar | Bincache |
| --- | ---: | ---: |
| startup, 10,000 paths | 52.162 ms | 54.237 ms |
| settled idle RSS, 10,000 paths | 3,008 KiB | 18,312 KiB |
| warm GET latency | 44.238 ms | 11.945 ms |
| warm Range latency | 48.907 ms | 0.338 ms |
| ordinary upload wall | 1,527.537 ms | 269.374 ms |
| concurrent upload wall | 1,491.296 ms | 198.082 ms |
| runtime closure | 46,807,008 bytes | 51,364,744 bytes |

The result confirms that the remaining performance work is in Narjar's
publication and request path, not idle arena retention: RSS remains small,
while metadata/Range and upload latency remain materially behind Bincache.
The next performance implementation is NARJ-109's dedicated publication
worker, with the existing streaming and bounded-queue constraints and no
jemalloc or `MALLOC_ARENA_MAX` workaround. Independently, the tracker’s
immediate verification priority is NARJ-112, which unblocks the urgent
real-Nix corpus issue NARJ-81.
