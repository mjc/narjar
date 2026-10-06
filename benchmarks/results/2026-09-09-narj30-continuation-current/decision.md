# NARJ-30 flat baseline

This is the corrected continuation run against the pinned
Bincache reference. It used three warmups, 15 measured repetitions, the
10,000-path corpus, identity HTTP encoding, and `compression=none` for both
candidates. `commands.txt` contains the commands and requests executed;
`samples.jsonl` contains the raw measurements.

Narjar completed the full benchmark. `samples.jsonl` contains
1,336 raw samples. Selected medians:

| Case | Narjar | Bincache |
| --- | ---: | ---: |
| startup, 10,000 paths | 52.162 ms | 54.237 ms |
| settled idle RSS, 10,000 paths | 3,008 KiB | 18,312 KiB |
| warm GET latency | 44.238 ms | 11.945 ms |
| warm Range latency | 48.907 ms | 0.338 ms |
| ordinary upload wall | 1,527.537 ms | 269.374 ms |
| concurrent upload wall | 1,491.296 ms | 198.082 ms |
| runtime closure | 46,807,008 bytes | 51,364,744 bytes |

In this run, RSS stayed small while metadata/Range and upload latency lagged
Bincache. The result pointed to publication and request handling rather than
idle arena retention.
