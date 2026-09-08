# Continuation benchmark

- bincache ref: `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`
- repetitions: 1
- random seed: 29030
- quick smoke run: yes; not decision evidence

| Case | Candidate | n | Median | p95 | Min | Max | Unit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| binary_size | bincache | 1 | 3724120.000 | 3724120.000 | 3724120.000 | 3724120.000 | bytes |
| binary_size | narjar | 1 | 1431168.000 | 1431168.000 | 1431168.000 | 1431168.000 | bytes |
| runtime_closure_size | bincache | 1 | 51957664.000 | 51957664.000 | 51957664.000 | 51957664.000 | bytes |
| runtime_closure_size | narjar | 1 | 44444720.000 | 44444720.000 | 44444720.000 | 44444720.000 | bytes |
| settled_idle_rss | bincache | 2 | 11454.000 | 11516.000 | 11392.000 | 11516.000 | KiB |
| settled_idle_rss | narjar | 2 | 2048.000 | 2096.000 | 2000.000 | 2096.000 | KiB |
| startup | bincache | 2 | 26.511 | 30.715 | 22.307 | 30.715 | ms |
| startup | narjar | 2 | 5.032 | 7.405 | 2.659 | 7.405 | ms |
