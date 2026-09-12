# Narjar publication concurrency

One throttled 1073741824-byte raw NAR upload at 67108864 bytes/sec was overlapped with independent small PUTs.

See [commands.txt](./commands.txt), [samples.tsv](./samples.tsv), [summary.tsv](./summary.tsv), and [metrics/](./metrics/).

```text
publishers	samples	p50_ms	p95_ms	p99_ms	min_ms	max_ms	slow_wall_ms	slow_mib_s	small_requests_s	server_cpu_ms	server_peak_rss_kib	queue_wait_count	queue_wait_sum_ms	queue_wait_max_ms
1	1	65.385	65.385	65.385	65.385	65.385	18569.935	55.143	15.294	1560.000	13080	2	0.059	0.031
2	2	53.447	53.541	53.541	53.447	53.541	18243.085	56.131	37.355	1910.000	13048	3	0.247	0.099
8	8	52.130	52.765	52.765	51.019	52.765	18119.638	56.513	151.616	1570.000	13312	9	0.507	0.074
32	32	76.261	82.064	100.397	69.667	100.397	18343.954	55.822	318.735	1940.000	14052	33	50.784	47.116
```
