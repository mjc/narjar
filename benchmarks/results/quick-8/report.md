# Continuation benchmark

- bincache ref: `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`
- repetitions: 1
- random seed: 29030
- quick smoke run: yes; not decision evidence

| Case | Candidate | n | Median | p95 | Min | Max | Unit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| binary_size | bincache | 1 | 3724120.000 | 3724120.000 | 3724120.000 | 3724120.000 | bytes |
| binary_size | narjar | 1 | 1431168.000 | 1431168.000 | 1431168.000 | 1431168.000 | bytes |
| concurrent_get_1 | bincache | 1 | 1202.553 | 1202.553 | 1202.553 | 1202.553 | MiB/s |
| concurrent_get_1 | narjar | 1 | 1327.150 | 1327.150 | 1327.150 | 1327.150 | MiB/s |
| concurrent_get_2 | bincache | 1 | 1597.400 | 1597.400 | 1597.400 | 1597.400 | MiB/s |
| concurrent_get_2 | narjar | 1 | 1431.913 | 1431.913 | 1431.913 | 1431.913 | MiB/s |
| get_cold_latency | bincache | 1 | 0.446 | 0.446 | 0.446 | 0.446 | ms |
| get_cold_latency | narjar | 1 | 0.753 | 0.753 | 0.753 | 0.753 | ms |
| get_cold_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_throughput | bincache | 1 | 2243.433 | 2243.433 | 2243.433 | 2243.433 | MiB/s |
| get_cold_throughput | narjar | 1 | 1327.802 | 1327.802 | 1327.802 | 1327.802 | MiB/s |
| get_warm_latency | bincache | 1 | 0.531 | 0.531 | 0.531 | 0.531 | ms |
| get_warm_latency | narjar | 1 | 0.699 | 0.699 | 0.699 | 0.699 | ms |
| get_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_throughput | bincache | 1 | 1884.597 | 1884.597 | 1884.597 | 1884.597 | MiB/s |
| get_warm_throughput | narjar | 1 | 1431.030 | 1431.030 | 1431.030 | 1431.030 | MiB/s |
| head_warm_latency | bincache | 1 | 0.165 | 0.165 | 0.165 | 0.165 | ms |
| head_warm_latency | narjar | 1 | 0.200 | 0.200 | 0.200 | 0.200 | ms |
| head_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| head_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| missing_404_latency | bincache | 1 | 0.170 | 0.170 | 0.170 | 0.170 | ms |
| missing_404_latency | narjar | 1 | 0.191 | 0.191 | 0.191 | 0.191 | ms |
| missing_404_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| range_warm_latency | bincache | 1 | 0.190 | 0.190 | 0.190 | 0.190 | ms |
| range_warm_latency | narjar | 1 | 0.201 | 0.201 | 0.201 | 0.201 | ms |
| range_warm_status | bincache | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| range_warm_status | narjar | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| runtime_closure_size | bincache | 1 | 51957664.000 | 51957664.000 | 51957664.000 | 51957664.000 | bytes |
| runtime_closure_size | narjar | 1 | 44444720.000 | 44444720.000 | 44444720.000 | 44444720.000 | bytes |
| settled_idle_rss_0_paths | bincache | 1 | 11476.000 | 11476.000 | 11476.000 | 11476.000 | KiB |
| settled_idle_rss_0_paths | narjar | 1 | 2004.000 | 2004.000 | 2004.000 | 2004.000 | KiB |
| settled_idle_rss_10_paths | bincache | 1 | 9444.000 | 9444.000 | 9444.000 | 9444.000 | KiB |
| settled_idle_rss_10_paths | narjar | 1 | 2024.000 | 2024.000 | 2024.000 | 2024.000 | KiB |
| startup_0_paths | bincache | 1 | 22.066 | 22.066 | 22.066 | 22.066 | ms |
| startup_0_paths | narjar | 1 | 5.117 | 5.117 | 5.117 | 5.117 | ms |
| startup_10_paths | bincache | 1 | 26.972 | 26.972 | 26.972 | 26.972 | ms |
| startup_10_paths | narjar | 1 | 4.918 | 4.918 | 4.918 | 4.918 | ms |
| upload_peak_rss | bincache | 1 | 14672.000 | 14672.000 | 14672.000 | 14672.000 | KiB |
| upload_peak_rss | narjar | 1 | 2084.000 | 2084.000 | 2084.000 | 2084.000 | KiB |
| upload_server_cpu | bincache | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_server_cpu | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_stored_bytes | bincache | 1 | 512.000 | 512.000 | 512.000 | 512.000 | bytes |
| upload_stored_bytes | narjar | 1 | 1024.000 | 1024.000 | 1024.000 | 1024.000 | bytes |
| upload_throughput | bincache | 1 | 15.179 | 15.179 | 15.179 | 15.179 | MiB/s |
| upload_throughput | narjar | 1 | 15.800 | 15.800 | 15.800 | 15.800 | MiB/s |
| upload_wall | bincache | 1 | 65.880 | 65.880 | 65.880 | 65.880 | ms |
| upload_wall | narjar | 1 | 63.291 | 63.291 | 63.291 | 63.291 | ms |
