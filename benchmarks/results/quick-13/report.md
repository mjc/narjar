# Continuation benchmark

- bincache ref: `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`
- repetitions: 1
- random seed: 29030
- quick smoke run: yes; not decision evidence

| Case | Candidate | n | Median | p95 | Min | Max | Unit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| binary_size | bincache | 1 | 3724120.000 | 3724120.000 | 3724120.000 | 3724120.000 | bytes |
| binary_size | narjar | 1 | 1431168.000 | 1431168.000 | 1431168.000 | 1431168.000 | bytes |
| concurrent_get_1 | bincache | 1 | 1021.313 | 1021.313 | 1021.313 | 1021.313 | MiB/s |
| concurrent_get_1 | narjar | 1 | 1228.871 | 1228.871 | 1228.871 | 1228.871 | MiB/s |
| concurrent_get_2 | bincache | 1 | 1424.499 | 1424.499 | 1424.499 | 1424.499 | MiB/s |
| concurrent_get_2 | narjar | 1 | 1274.545 | 1274.545 | 1274.545 | 1274.545 | MiB/s |
| concurrent_upload_peak_rss | bincache | 1 | 24104.000 | 24104.000 | 24104.000 | 24104.000 | KiB |
| concurrent_upload_peak_rss | narjar | 1 | 2288.000 | 2288.000 | 2288.000 | 2288.000 | KiB |
| concurrent_upload_server_cpu | bincache | 1 | 10.000 | 10.000 | 10.000 | 10.000 | ms |
| concurrent_upload_server_cpu | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| concurrent_upload_wall | bincache | 1 | 82.613 | 82.613 | 82.613 | 82.613 | ms |
| concurrent_upload_wall | narjar | 1 | 87.749 | 87.749 | 87.749 | 87.749 | ms |
| correct_key_substituted | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| correct_key_substituted | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| duplicate_upload_stored_bytes | bincache | 1 | 0.000 | 0.000 | 0.000 | 0.000 | bytes |
| duplicate_upload_stored_bytes | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | bytes |
| duplicate_upload_wall | bincache | 1 | 25.075 | 25.075 | 25.075 | 25.075 | ms |
| duplicate_upload_wall | narjar | 1 | 27.304 | 27.304 | 27.304 | 27.304 | ms |
| enospc_client_failed | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_client_failed | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_service_alive | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_service_alive | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_visibility_after_failure | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| enospc_visibility_after_failure | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| enospc_visibility_after_restart | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| enospc_visibility_after_restart | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| get_cold_latency | bincache | 1 | 0.520 | 0.520 | 0.520 | 0.520 | ms |
| get_cold_latency | narjar | 1 | 0.864 | 0.864 | 0.864 | 0.864 | ms |
| get_cold_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_throughput | bincache | 1 | 1924.818 | 1924.818 | 1924.818 | 1924.818 | MiB/s |
| get_cold_throughput | narjar | 1 | 1158.180 | 1158.180 | 1158.180 | 1158.180 | MiB/s |
| get_warm_latency | bincache | 1 | 0.492 | 0.492 | 0.492 | 0.492 | ms |
| get_warm_latency | narjar | 1 | 0.548 | 0.548 | 0.548 | 0.548 | ms |
| get_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_throughput | bincache | 1 | 2031.404 | 2031.404 | 2031.404 | 2031.404 | MiB/s |
| get_warm_throughput | narjar | 1 | 1823.582 | 1823.582 | 1823.582 | 1823.582 | MiB/s |
| head_warm_latency | bincache | 1 | 0.183 | 0.183 | 0.183 | 0.183 | ms |
| head_warm_latency | narjar | 1 | 0.279 | 0.279 | 0.279 | 0.279 | ms |
| head_warm_status | bincache | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| head_warm_status | narjar | 1 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| interrupted_upload_recovery_wall | bincache | 1 | 26.515 | 26.515 | 26.515 | 26.515 | ms |
| interrupted_upload_recovery_wall | narjar | 1 | 4.822 | 4.822 | 4.822 | 4.822 | ms |
| interrupted_upload_restart_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| interrupted_upload_restart_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| interrupted_upload_server_alive | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| interrupted_upload_server_alive | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| interrupted_upload_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| interrupted_upload_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_latency | bincache | 1 | 0.169 | 0.169 | 0.169 | 0.169 | ms |
| missing_404_latency | narjar | 1 | 0.201 | 0.201 | 0.201 | 0.201 | ms |
| missing_404_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| range_warm_latency | bincache | 1 | 0.199 | 0.199 | 0.199 | 0.199 | ms |
| range_warm_latency | narjar | 1 | 0.214 | 0.214 | 0.214 | 0.214 | ms |
| range_warm_status | bincache | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| range_warm_status | narjar | 1 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| reconcile_steps | bincache | 1 | 3.000 | 3.000 | 3.000 | 3.000 | steps |
| reconcile_steps | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | steps |
| reconcile_wall | bincache | 1 | 34.724 | 34.724 | 34.724 | 34.724 | ms |
| reconcile_wall | narjar | 1 | 4.822 | 4.822 | 4.822 | 4.822 | ms |
| runtime_closure_size | bincache | 1 | 51957664.000 | 51957664.000 | 51957664.000 | 51957664.000 | bytes |
| runtime_closure_size | narjar | 1 | 44444720.000 | 44444720.000 | 44444720.000 | 44444720.000 | bytes |
| settled_idle_rss_0_paths | bincache | 1 | 11528.000 | 11528.000 | 11528.000 | 11528.000 | KiB |
| settled_idle_rss_0_paths | narjar | 1 | 2064.000 | 2064.000 | 2064.000 | 2064.000 | KiB |
| settled_idle_rss_10_paths | bincache | 1 | 11548.000 | 11548.000 | 11548.000 | 11548.000 | KiB |
| settled_idle_rss_10_paths | narjar | 1 | 2076.000 | 2076.000 | 2076.000 | 2076.000 | KiB |
| startup_0_paths | bincache | 1 | 22.262 | 22.262 | 22.262 | 22.262 | ms |
| startup_0_paths | narjar | 1 | 7.237 | 7.237 | 7.237 | 7.237 | ms |
| startup_10_paths | bincache | 1 | 24.422 | 24.422 | 24.422 | 24.422 | ms |
| startup_10_paths | narjar | 1 | 4.762 | 4.762 | 4.762 | 4.762 | ms |
| streaming_upload_peak_rss_4194304_bytes | bincache | 1 | 23124.000 | 23124.000 | 23124.000 | 23124.000 | KiB |
| streaming_upload_peak_rss_4194304_bytes | narjar | 1 | 2208.000 | 2208.000 | 2208.000 | 2208.000 | KiB |
| streaming_upload_server_cpu_4194304_bytes | bincache | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| streaming_upload_server_cpu_4194304_bytes | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| streaming_upload_stored_bytes_4194304_bytes | bincache | 1 | 4194521.000 | 4194521.000 | 4194521.000 | 4194521.000 | bytes |
| streaming_upload_stored_bytes_4194304_bytes | narjar | 1 | 4195280.000 | 4195280.000 | 4195280.000 | 4195280.000 | bytes |
| streaming_upload_wall_4194304_bytes | bincache | 1 | 72.314 | 72.314 | 72.314 | 72.314 | ms |
| streaming_upload_wall_4194304_bytes | narjar | 1 | 72.215 | 72.215 | 72.215 | 72.215 | ms |
| upload_peak_rss | bincache | 1 | 21916.000 | 21916.000 | 21916.000 | 21916.000 | KiB |
| upload_peak_rss | narjar | 1 | 2200.000 | 2200.000 | 2200.000 | 2200.000 | KiB |
| upload_server_cpu | bincache | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_server_cpu | narjar | 1 | 0.000 | 0.000 | 0.000 | 0.000 | ms |
| upload_stored_bytes | bincache | 1 | 1048721.000 | 1048721.000 | 1048721.000 | 1048721.000 | bytes |
| upload_stored_bytes | narjar | 1 | 1049549.000 | 1049549.000 | 1049549.000 | 1049549.000 | bytes |
| upload_throughput | bincache | 1 | 17.644 | 17.644 | 17.644 | 17.644 | MiB/s |
| upload_throughput | narjar | 1 | 16.338 | 16.338 | 16.338 | 16.338 | MiB/s |
| upload_wall | bincache | 1 | 56.677 | 56.677 | 56.677 | 56.677 | ms |
| upload_wall | narjar | 1 | 61.209 | 61.209 | 61.209 | 61.209 | ms |
| wrong_key_rejected | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| wrong_key_rejected | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
