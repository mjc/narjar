# Continuation benchmark

- bincache ref: `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`
- repetitions: 1
- random seed: 29030
- quick smoke run: yes; not decision evidence

| Case | Candidate | n | Median | p95 | Min | Max | Unit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| binary_size | bincache | 1 | 3724120.000 | 3724120.000 | 3724120.000 | 3724120.000 | bytes |
| binary_size | narjar | 1 | 1431168.000 | 1431168.000 | 1431168.000 | 1431168.000 | bytes |
| concurrent_get_1 | bincache | 1 | 1290.083 | 1290.083 | 1290.083 | 1290.083 | MiB/s |
| concurrent_get_1 | narjar | 1 | 1163.299 | 1163.299 | 1163.299 | 1163.299 | MiB/s |
| concurrent_get_2 | bincache | 1 | 1803.509 | 1803.509 | 1803.509 | 1803.509 | MiB/s |
| concurrent_get_2 | narjar | 1 | 1297.057 | 1297.057 | 1297.057 | 1297.057 | MiB/s |
| get_cold_latency | bincache | 1 | 0.460 | 0.460 | 0.460 | 0.460 | ms |
| get_cold_latency | narjar | 1 | 0.636 | 0.636 | 0.636 | 0.636 | ms |
| get_cold_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_throughput | bincache | 1 | 2174.996 | 2174.996 | 2174.996 | 2174.996 | MiB/s |
| get_cold_throughput | narjar | 1 | 1572.018 | 1572.018 | 1572.018 | 1572.018 | MiB/s |
| get_warm_latency | bincache | 1 | 0.542 | 0.542 | 0.542 | 0.542 | ms |
| get_warm_latency | narjar | 1 | 0.716 | 0.716 | 0.716 | 0.716 | ms |
| get_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_throughput | bincache | 1 | 1845.709 | 1845.709 | 1845.709 | 1845.709 | MiB/s |
| get_warm_throughput | narjar | 1 | 1396.282 | 1396.282 | 1396.282 | 1396.282 | MiB/s |
| head_warm_latency | bincache | 1 | 0.165 | 0.165 | 0.165 | 0.165 | ms |
| head_warm_latency | narjar | 1 | 0.186 | 0.186 | 0.186 | 0.186 | ms |
| head_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| head_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| missing_404_latency | bincache | 1 | 0.166 | 0.166 | 0.166 | 0.166 | ms |
| missing_404_latency | narjar | 1 | 0.190 | 0.190 | 0.190 | 0.190 | ms |
| missing_404_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| range_warm_latency | bincache | 1 | 0.184 | 0.184 | 0.184 | 0.184 | ms |
| range_warm_latency | narjar | 1 | 0.221 | 0.221 | 0.221 | 0.221 | ms |
| range_warm_status | bincache | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| range_warm_status | narjar | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| runtime_closure_size | bincache | 1 | 51957664.000 | 51957664.000 | 51957664.000 | 51957664.000 | bytes |
| runtime_closure_size | narjar | 1 | 44444720.000 | 44444720.000 | 44444720.000 | 44444720.000 | bytes |
| settled_idle_rss_0_paths | bincache | 1 | 11512.000 | 11512.000 | 11512.000 | 11512.000 | KiB |
| settled_idle_rss_0_paths | narjar | 1 | 2052.000 | 2052.000 | 2052.000 | 2052.000 | KiB |
| settled_idle_rss_10_paths | bincache | 1 | 11560.000 | 11560.000 | 11560.000 | 11560.000 | KiB |
| settled_idle_rss_10_paths | narjar | 1 | 2072.000 | 2072.000 | 2072.000 | 2072.000 | KiB |
| startup_0_paths | bincache | 1 | 24.524 | 24.524 | 24.524 | 24.524 | ms |
| startup_0_paths | narjar | 1 | 5.223 | 5.223 | 5.223 | 5.223 | ms |
| startup_10_paths | bincache | 1 | 22.334 | 22.334 | 22.334 | 22.334 | ms |
| startup_10_paths | narjar | 1 | 5.102 | 5.102 | 5.102 | 5.102 | ms |
| upload_peak_rss | bincache | 1 | 21920.000 | 21920.000 | 21920.000 | 21920.000 | KiB |
| upload_peak_rss | narjar | 1 | 2224.000 | 2224.000 | 2224.000 | 2224.000 | KiB |
| upload_server_cpu | bincache | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_server_cpu | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_stored_bytes | bincache | 1 | 1048721.000 | 1048721.000 | 1048721.000 | 1048721.000 | bytes |
| upload_stored_bytes | narjar | 1 | 1049438.000 | 1049438.000 | 1049438.000 | 1049438.000 | bytes |
| upload_throughput | bincache | 1 | 21.669 | 21.669 | 21.669 | 21.669 | MiB/s |
| upload_throughput | narjar | 1 | 14.827 | 14.827 | 14.827 | 14.827 | MiB/s |
| upload_wall | bincache | 1 | 46.149 | 46.149 | 46.149 | 46.149 | ms |
| upload_wall | narjar | 1 | 67.447 | 67.447 | 67.447 | 67.447 | ms |
