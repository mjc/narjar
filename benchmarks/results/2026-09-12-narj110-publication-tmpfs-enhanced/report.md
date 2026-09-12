# Narjar publication concurrency on tmpfs

One throttled 16777216-byte raw NAR upload at 4194304 bytes/sec was overlapped with independent small PUTs.

The data directory and payloads were on `/dev/shm` (`tmpfs`). The run used the
release binary and 1, 2, 8, and 32 small publishers. `server_peak_rss_kib` is
the largest `/proc/<pid>/smaps_rollup` RSS observed; `server_post_load_rss_kib`
is the value after all uploads completed. The anonymous fields include glibc
allocator mappings that are not necessarily reported as the main `[heap]`
mapping. `server_peak_staging_bytes` is the largest `du -sb` total for the two
staging directories. `recovery_ms` measures restart through the health check
after a durable synthetic transaction record was installed.

See [commands.txt](./commands.txt), [samples.tsv](./samples.tsv), [summary.tsv](./summary.tsv), and [metrics/](./metrics/).

```text
publishers	samples	p50_ms	p95_ms	p99_ms	min_ms	max_ms	slow_wall_ms	slow_mib_s	small_requests_s	server_cpu_ms	server_peak_rss_kib	server_post_load_rss_kib	server_peak_anonymous_kib	server_post_load_anonymous_kib	server_peak_heap_rss_kib	server_peak_staging_bytes	recovery_ms	queue_wait_count	queue_wait_sum_ms	queue_wait_max_ms
1	1	28.752	28.752	28.752	28.752	28.752	5080.068	3.150	34.780	0.000	12152	12152	9620	9620	92	12582912	55.759	2	0.086	0.045
2	2	30.237	30.253	30.253	30.237	30.253	5046.357	3.171	66.109	0.000	12204	12204	9672	9672	92	12582912	55.428	3	0.103	0.042
8	8	29.713	29.822	29.822	29.428	29.822	5066.702	3.158	268.258	10.000	12500	12500	9968	9968	92	12582912	58.176	9	0.447	0.066
32	32	6.961	50.130	50.607	2.622	50.607	5089.628	3.144	632.324	0.000	13444	13444	10912	10912	92	12582912	58.030	33	6.296	0.567
```
