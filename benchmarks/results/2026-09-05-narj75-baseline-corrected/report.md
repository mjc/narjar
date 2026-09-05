# Continuation benchmark

- bincache ref: `556a9c8f97a3c994a9de85f567a2ef16ce6513ab`
- warmups: 3
- repetitions: 15
- random seed: 29030
- quick smoke run: no

| Case | Candidate | n | Median | p95 | Min | Max | Unit |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| binary_size | bincache | 1 | 3723296.000 | 3723296.000 | 3723296.000 | 3723296.000 | bytes |
| binary_size | narjar | 1 | 2062960.000 | 2062960.000 | 2062960.000 | 2062960.000 | bytes |
| binary_size | narjar-static | 1 | 2193072.000 | 2193072.000 | 2193072.000 | 2193072.000 | bytes |
| concurrent_get_1 | bincache | 15 | 1610.323 | 1856.917 | 920.592 | 1856.917 | MiB/s |
| concurrent_get_1 | narjar | 15 | 336.453 | 868.432 | 263.960 | 868.432 | MiB/s |
| concurrent_get_32 | bincache | 15 | 1548.990 | 2268.157 | 1163.447 | 2268.157 | MiB/s |
| concurrent_get_32 | narjar | 15 | 1666.454 | 1893.746 | 1153.228 | 1893.746 | MiB/s |
| concurrent_get_8 | bincache | 15 | 1499.696 | 2241.623 | 1358.218 | 2241.623 | MiB/s |
| concurrent_get_8 | narjar | 15 | 1163.044 | 1950.176 | 949.467 | 1950.176 | MiB/s |
| concurrent_upload_peak_rss | bincache | 15 | 33432.000 | 39156.000 | 26936.000 | 39156.000 | KiB |
| concurrent_upload_peak_rss | narjar | 15 | 3148.000 | 3148.000 | 3148.000 | 3148.000 | KiB |
| concurrent_upload_server_cpu | bincache | 15 | 20.000 | 30.000 | 0.000 | 30.000 | ms |
| concurrent_upload_server_cpu | narjar | 15 | 10.000 | 20.000 | 0.000 | 20.000 | ms |
| concurrent_upload_wall | bincache | 15 | 104.686 | 136.554 | 99.490 | 136.554 | ms |
| concurrent_upload_wall | narjar | 15 | 1358.923 | 1390.982 | 1348.645 | 1390.982 | ms |
| correct_key_substituted | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| correct_key_substituted | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| duplicate_upload_stored_bytes | bincache | 15 | 0.000 | 0.000 | 0.000 | 0.000 | bytes |
| duplicate_upload_stored_bytes | narjar | 15 | 0.000 | 0.000 | 0.000 | 0.000 | bytes |
| duplicate_upload_wall | bincache | 15 | 27.074 | 29.146 | 25.208 | 29.146 | ms |
| duplicate_upload_wall | narjar | 15 | 58.643 | 69.286 | 37.199 | 69.286 | ms |
| enospc_client_failed | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_client_failed | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_service_alive | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_service_alive | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| enospc_visibility_after_failure | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| enospc_visibility_after_failure | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| enospc_visibility_after_restart | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| enospc_visibility_after_restart | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP status |
| get_cold_latency | bincache | 15 | 10.617 | 13.858 | 8.477 | 13.858 | ms |
| get_cold_latency | narjar | 15 | 46.381 | 58.831 | 9.921 | 58.831 | ms |
| get_cold_status | bincache | 15 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_status | narjar | 15 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_cold_throughput | bincache | 15 | 1507.067 | 1887.373 | 1154.569 | 1887.373 | MiB/s |
| get_cold_throughput | narjar | 15 | 344.970 | 1612.797 | 271.969 | 1612.797 | MiB/s |
| get_warm_latency | bincache | 15 | 8.071 | 10.511 | 7.033 | 10.511 | ms |
| get_warm_latency | narjar | 15 | 40.879 | 53.536 | 18.920 | 53.536 | ms |
| get_warm_status | bincache | 15 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_status | narjar | 15 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| get_warm_throughput | bincache | 15 | 1982.513 | 2274.922 | 1522.246 | 2274.922 | MiB/s |
| get_warm_throughput | narjar | 15 | 391.402 | 845.678 | 298.867 | 845.678 | MiB/s |
| head_warm_latency | bincache | 15 | 0.280 | 0.336 | 0.170 | 0.336 | ms |
| head_warm_latency | narjar | 15 | 49.445 | 49.900 | 46.454 | 49.900 | ms |
| head_warm_status | bincache | 15 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| head_warm_status | narjar | 15 | 200.000 | 200.000 | 200.000 | 200.000 | HTTP |
| interrupted_upload_recovery_wall | bincache | 1 | 30.636 | 30.636 | 30.636 | 30.636 | ms |
| interrupted_upload_recovery_wall | narjar | 1 | 51.256 | 51.256 | 51.256 | 51.256 | ms |
| interrupted_upload_restart_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| interrupted_upload_restart_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| interrupted_upload_server_alive | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| interrupted_upload_server_alive | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| interrupted_upload_status | bincache | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| interrupted_upload_status | narjar | 1 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_latency | bincache | 15 | 0.284 | 0.355 | 0.180 | 0.355 | ms |
| missing_404_latency | narjar | 15 | 49.509 | 49.997 | 48.389 | 49.997 | ms |
| missing_404_status | bincache | 15 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| missing_404_status | narjar | 15 | 404.000 | 404.000 | 404.000 | 404.000 | HTTP |
| range_warm_latency | bincache | 15 | 0.214 | 0.432 | 0.177 | 0.432 | ms |
| range_warm_latency | narjar | 15 | 49.737 | 49.996 | 48.274 | 49.996 | ms |
| range_warm_status | bincache | 15 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| range_warm_status | narjar | 15 | 206.000 | 206.000 | 206.000 | 206.000 | HTTP |
| reconcile_steps | bincache | 1 | 3.000 | 3.000 | 3.000 | 3.000 | steps |
| reconcile_steps | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | steps |
| reconcile_wall | bincache | 1 | 55.472 | 55.472 | 55.472 | 55.472 | ms |
| reconcile_wall | narjar | 1 | 51.256 | 51.256 | 51.256 | 51.256 | ms |
| runtime_closure_size | bincache | 1 | 51956840.000 | 51956840.000 | 51956840.000 | 51956840.000 | bytes |
| runtime_closure_size | narjar | 1 | 45076512.000 | 45076512.000 | 45076512.000 | 45076512.000 | bytes |
| runtime_closure_size | narjar-static | 1 | 2193552.000 | 2193552.000 | 2193552.000 | 2193552.000 | bytes |
| settled_idle_rss_0_paths | bincache | 15 | 12296.000 | 12300.000 | 12296.000 | 12300.000 | KiB |
| settled_idle_rss_0_paths | narjar | 15 | 3072.000 | 3072.000 | 3072.000 | 3072.000 | KiB |
| settled_idle_rss_10000_paths | bincache | 15 | 18440.000 | 18444.000 | 18440.000 | 18444.000 | KiB |
| settled_idle_rss_10000_paths | narjar | 15 | 3072.000 | 3072.000 | 3072.000 | 3072.000 | KiB |
| settled_idle_rss_1000_paths | bincache | 15 | 10248.000 | 10252.000 | 10248.000 | 10252.000 | KiB |
| settled_idle_rss_1000_paths | narjar | 15 | 3072.000 | 3072.000 | 3072.000 | 3072.000 | KiB |
| settled_idle_rss_100_paths | bincache | 15 | 12296.000 | 12300.000 | 12296.000 | 12300.000 | KiB |
| settled_idle_rss_100_paths | narjar | 15 | 3072.000 | 3072.000 | 3072.000 | 3072.000 | KiB |
| startup_0_paths | bincache | 15 | 22.543 | 43.900 | 22.221 | 43.900 | ms |
| startup_0_paths | narjar | 15 | 51.251 | 51.376 | 50.973 | 51.376 | ms |
| startup_10000_paths | bincache | 15 | 26.552 | 44.159 | 24.072 | 44.159 | ms |
| startup_10000_paths | narjar | 15 | 51.276 | 51.482 | 51.135 | 51.482 | ms |
| startup_1000_paths | bincache | 15 | 26.550 | 52.298 | 22.118 | 52.298 | ms |
| startup_1000_paths | narjar | 15 | 51.265 | 51.400 | 51.080 | 51.400 | ms |
| startup_100_paths | bincache | 15 | 22.496 | 82.083 | 22.156 | 82.083 | ms |
| startup_100_paths | narjar | 15 | 51.231 | 51.418 | 51.079 | 51.418 | ms |
| streaming_upload_peak_rss_104857600_bytes | bincache | 1 | 19948.000 | 19948.000 | 19948.000 | 19948.000 | KiB |
| streaming_upload_peak_rss_104857600_bytes | narjar | 1 | 3116.000 | 3116.000 | 3116.000 | 3116.000 | KiB |
| streaming_upload_peak_rss_1073741824_bytes | bincache | 1 | 25884.000 | 25884.000 | 25884.000 | 25884.000 | KiB |
| streaming_upload_peak_rss_1073741824_bytes | narjar | 1 | 3116.000 | 3116.000 | 3116.000 | 3116.000 | KiB |
| streaming_upload_server_cpu_104857600_bytes | bincache | 1 | 160.000 | 160.000 | 160.000 | 160.000 | ms |
| streaming_upload_server_cpu_104857600_bytes | narjar | 1 | 130.000 | 130.000 | 130.000 | 130.000 | ms |
| streaming_upload_server_cpu_1073741824_bytes | bincache | 1 | 1720.000 | 1720.000 | 1720.000 | 1720.000 | ms |
| streaming_upload_server_cpu_1073741824_bytes | narjar | 1 | 1300.000 | 1300.000 | 1300.000 | 1300.000 | ms |
| streaming_upload_stored_bytes_104857600_bytes | bincache | 1 | 104860121.000 | 104860121.000 | 104860121.000 | 104860121.000 | bytes |
| streaming_upload_stored_bytes_104857600_bytes | narjar | 1 | 104858249.000 | 104858249.000 | 104858249.000 | 104858249.000 | bytes |
| streaming_upload_stored_bytes_1073741824_bytes | bincache | 1 | 1073766521.000 | 1073766521.000 | 1073766521.000 | 1073766521.000 | bytes |
| streaming_upload_stored_bytes_1073741824_bytes | narjar | 1 | 1073742476.000 | 1073742476.000 | 1073742476.000 | 1073742476.000 | bytes |
| streaming_upload_wall_104857600_bytes | bincache | 1 | 612.460 | 612.460 | 612.460 | 612.460 | ms |
| streaming_upload_wall_104857600_bytes | narjar | 1 | 1913.360 | 1913.360 | 1913.360 | 1913.360 | ms |
| streaming_upload_wall_1073741824_bytes | bincache | 1 | 7981.504 | 7981.504 | 7981.504 | 7981.504 | ms |
| streaming_upload_wall_1073741824_bytes | narjar | 1 | 7591.933 | 7591.933 | 7591.933 | 7591.933 | ms |
| upload_peak_rss | bincache | 15 | 24724.000 | 28032.000 | 22728.000 | 28032.000 | KiB |
| upload_peak_rss | narjar | 15 | 3116.000 | 3116.000 | 3116.000 | 3116.000 | KiB |
| upload_server_cpu | bincache | 15 | 30.000 | 40.000 | 20.000 | 40.000 | ms |
| upload_server_cpu | narjar | 15 | 20.000 | 30.000 | 10.000 | 30.000 | ms |
| upload_stored_bytes | bincache | 15 | 16777721.000 | 16777721.000 | 16777721.000 | 16777721.000 | bytes |
| upload_stored_bytes | narjar | 15 | 16777970.000 | 16777971.000 | 16777860.000 | 16777971.000 | bytes |
| upload_throughput | bincache | 15 | 109.760 | 121.313 | 90.419 | 121.313 | MiB/s |
| upload_throughput | narjar | 15 | 11.662 | 11.857 | 11.020 | 11.857 | MiB/s |
| upload_wall | bincache | 15 | 145.773 | 176.953 | 131.890 | 176.953 | ms |
| upload_wall | narjar | 15 | 1371.955 | 1451.911 | 1349.431 | 1451.911 | ms |
| wrong_key_rejected | bincache | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
| wrong_key_rejected | narjar | 1 | 1.000 | 1.000 | 1.000 | 1.000 | bool |
