# Continuation benchmark

- bincache ref: `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`
- repetitions: 1
- random seed: 29030
- quick smoke run: yes; not decision evidence

| Case | Candidate | n | Median | p95 | Min | Max | Unit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| binary_size | bincache | 1 | 3724120.000 | 3724120.000 | 3724120.000 | 3724120.000 | bytes |
| binary_size | narjar | 1 | 1431168.000 | 1431168.000 | 1431168.000 | 1431168.000 | bytes |
| concurrent_get_1 | bincache | 1 | 2495.974 | 2495.974 | 2495.974 | 2495.974 | MiB/s |
| concurrent_get_1 | narjar | 1 | 1138.384 | 1138.384 | 1138.384 | 1138.384 | MiB/s |
| concurrent_get_2 | bincache | 1 | 2765.293 | 2765.293 | 2765.293 | 2765.293 | MiB/s |
| concurrent_get_2 | narjar | 1 | 1324.226 | 1324.226 | 1324.226 | 1324.226 | MiB/s |
| get_cold_latency | bincache | 1 | 0.202 | 0.202 | 0.202 | 0.202 | ms |
| get_cold_latency | narjar | 1 | 0.744 | 0.744 | 0.744 | 0.744 | ms |
| get_cold_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_throughput | bincache | 1 | 4946.812 | 4946.812 | 4946.812 | 4946.812 | MiB/s |
| get_cold_throughput | narjar | 1 | 1345.030 | 1345.030 | 1345.030 | 1345.030 | MiB/s |
| get_warm_latency | bincache | 1 | 0.218 | 0.218 | 0.218 | 0.218 | ms |
| get_warm_latency | narjar | 1 | 0.667 | 0.667 | 0.667 | 0.667 | ms |
| get_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_throughput | bincache | 1 | 4591.184 | 4591.184 | 4591.184 | 4591.184 | MiB/s |
| get_warm_throughput | narjar | 1 | 1499.611 | 1499.611 | 1499.611 | 1499.611 | MiB/s |
| head_warm_latency | bincache | 1 | 0.174 | 0.174 | 0.174 | 0.174 | ms |
| head_warm_latency | narjar | 1 | 0.182 | 0.182 | 0.182 | 0.182 | ms |
| head_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| head_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| missing_404_latency | bincache | 1 | 0.170 | 0.170 | 0.170 | 0.170 | ms |
| missing_404_latency | narjar | 1 | 0.185 | 0.185 | 0.185 | 0.185 | ms |
| missing_404_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| range_warm_latency | bincache | 1 | 0.186 | 0.186 | 0.186 | 0.186 | ms |
| range_warm_latency | narjar | 1 | 0.201 | 0.201 | 0.201 | 0.201 | ms |
| range_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| range_warm_status | narjar | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| runtime_closure_size | bincache | 1 | 51957664.000 | 51957664.000 | 51957664.000 | 51957664.000 | bytes |
| runtime_closure_size | narjar | 1 | 44444720.000 | 44444720.000 | 44444720.000 | 44444720.000 | bytes |
| settled_idle_rss_0_paths | bincache | 1 | 11552.000 | 11552.000 | 11552.000 | 11552.000 | KiB |
| settled_idle_rss_0_paths | narjar | 1 | 2052.000 | 2052.000 | 2052.000 | 2052.000 | KiB |
| settled_idle_rss_10_paths | bincache | 1 | 11560.000 | 11560.000 | 11560.000 | 11560.000 | KiB |
| settled_idle_rss_10_paths | narjar | 1 | 2064.000 | 2064.000 | 2064.000 | 2064.000 | KiB |
| startup_0_paths | bincache | 1 | 31.623 | 31.623 | 31.623 | 31.623 | ms |
| startup_0_paths | narjar | 1 | 5.251 | 5.251 | 5.251 | 5.251 | ms |
| startup_10_paths | bincache | 1 | 27.327 | 27.327 | 27.327 | 27.327 | ms |
| startup_10_paths | narjar | 1 | 2.739 | 2.739 | 2.739 | 2.739 | ms |
| upload_peak_rss | bincache | 1 | 13516.000 | 13516.000 | 13516.000 | 13516.000 | KiB |
| upload_peak_rss | narjar | 1 | 2076.000 | 2076.000 | 2076.000 | 2076.000 | KiB |
| upload_server_cpu | bincache | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_server_cpu | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_stored_bytes | bincache | 1 | 512.000 | 512.000 | 512.000 | 512.000 | bytes |
| upload_stored_bytes | narjar | 1 | 1024.000 | 1024.000 | 1024.000 | 1024.000 | bytes |
| upload_throughput | bincache | 1 | 22.816 | 22.816 | 22.816 | 22.816 | MiB/s |
| upload_throughput | narjar | 1 | 16.731 | 16.731 | 16.731 | 16.731 | MiB/s |
| upload_wall | bincache | 1 | 43.829 | 43.829 | 43.829 | 43.829 | ms |
| upload_wall | narjar | 1 | 59.769 | 59.769 | 59.769 | 59.769 | ms |
