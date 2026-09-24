# narjar

Narjar is a small, filesystem-backed HTTP binary cache for Nix. It stores NAR
files and signed narinfo files as immutable objects. The server does not need a
Nix installation, database, signing private key, or online garbage collector.

The detailed protocol and operational rules are in [`docs/`](docs/), especially
[`docs/protocol-v0.1.md`](docs/protocol-v0.1.md) and
[`docs/operations.md`](docs/operations.md). The measured publication-lock
decision is recorded in [`docs/publication-lock-adr.md`](docs/publication-lock-adr.md).

## Quick start

Narjar needs a data directory. `init` creates it and refuses to reuse a
non-empty directory.

```sh
nix run . -- init --data-dir ./cache
nix run . -- token create --data-dir ./cache --scope write --name local > ./write.token
chmod 600 ./write.token
nix run . -- serve --data-dir ./cache --listen 127.0.0.1:5000
```

The server defaults are loopback on port `5000`, eight workers, a 64-request
in-flight limit, a 16 GiB maximum NAR size, and a 1 GiB free-space reserve.
Override them with `serve` flags or the matching `NARJAR_*` environment
variables:

| Flag | Environment variable |
| --- | --- |
| `--data-dir` | `NARJAR_DATA_DIR` |
| `--listen` | `NARJAR_LISTEN` |
| `--workers` | `NARJAR_WORKERS` |
| `--max-in-flight` | `NARJAR_MAX_IN_FLIGHT` |
| `--max-nar-bytes` | `NARJAR_MAX_NAR_BYTES` |
| `--min-free-bytes` | `NARJAR_MIN_FREE_BYTES` |
| `--egress-compression` | `NARJAR_EGRESS_COMPRESSION` |

Put the service behind a TLS reverse proxy when it is not strictly local.
Narjar itself speaks HTTP and supports public or token-authenticated reads plus
token-authenticated writes.

## Push a Nix closure

Narjar accepts client-signed Nix metadata. Generate a producer key, trust its
public half in the cache, and keep the secret half outside the data directory:

```sh
nix run . -- key generate \
  --name local-producer \
  --secret-key-file ./producer.sec \
  --public-key-file ./producer.pub
chmod 600 ./producer.sec
cp ./producer.pub ./cache/trusted-public-keys
```

Create a netrc containing the write token. The `push` command reads the local
store database, serializes and signs the closure in Rust, then performs the NAR
and narinfo HTTP uploads:

```sh
printf 'machine 127.0.0.1 login narjar password %s\n' "$(cat ./write.token)" > ./narjar.netrc
chmod 600 ./narjar.netrc

nix run . -- push \
  --to http://127.0.0.1:5000 \
  --netrc-file ./narjar.netrc \
  --insecure-http \
  --signing-key-file ./producer.sec \
  --compression none \
  --jobs 8 \
  /nix/store/some-package
```

Use `--refresh` to re-check and re-upload paths already present at the
destination. `--compression` is explicit and accepts `none`, `zstd`, or `xz`; it
controls only the upload representation and defaults to `none`. The server
independently selects the representation advertised to readers with
`--egress-compression`, which also accepts `none`, `zstd`, or `xz` and defaults
to `none`. Raw NAR bytes remain the authoritative stored object; a compressed
egress file is materialized and published only after the raw object is durable.
Netrc credentials are sent only over HTTPS by default;
`--insecure-http` is an explicit opt-in for the loopback HTTP example above.
The client uses fixed-length requests, streams canonical NAR bytes directly
from the local store, and authenticates with the matching netrc entry. The native HTTP request
timeout defaults to 30 seconds and can be changed with
`--timeout-seconds` or `NARJAR_PUSH_TIMEOUT_SECONDS`. The server publishes the
NAR before its narinfo, and consumers only see a path after the metadata is
durable. The push command does not invoke `nix copy` or any other Nix
subprocess; it requires the local Nix store and its SQLite metadata database,
and currently accepts concrete store paths rather than Nix expressions or flake
installables. Referenced store paths are uploaded in deterministic
dependency waves; independent paths within a wave use the bounded `--jobs`
parallelism.

To avoid copying closure members already available from caches that every
consumer can reach, list those caches in lookup order and provide their trusted
Nix public keys explicitly:

```sh
nix run . -- push \
  --to https://cache.example \
  --trusted-upstream https://cache.nixos.org \
  --trusted-upstream-key 'https://cache.nixos.org#cache.nixos.org-1:BASE64_PUBLIC_KEY' \
  --signing-key-file ./producer.sec \
  /nix/store/some-package
```

Narjar checks the destination first. After a destination miss, it accepts an
upstream hit only when the bounded narinfo has a trusted signature and its
store path, NAR hash, NAR size, and references exactly match the local store
metadata. It never downloads the upstream payload for this decision. Upstream
404s, connection failures, 5xx responses, invalid signatures, and metadata
mismatches fall back to the normal upload and produce a diagnostic. Repeating
`--trusted-upstream` preserves command-line order; repeated
`--trusted-upstream-key` values bind each key explicitly to an upstream using
`UPSTREAM#NAME:BASE64`; repeat the binding for key rotation.

Configuring an upstream is an assertion that cache consumers can also reach
it, either as another Nix substituter or through a read-through Narjar edge.
Narjar does not copy skipped upstream objects into the destination, and it does
not verify that the upstream payload exists when it accepts a matching narinfo.
This is a metadata-only availability decision: a stale narinfo or missing
upstream payload can still make a later substitution fail. `--refresh` forces
uploads and bypasses both destination and upstream skip decisions.

## Inspect and maintain a cache

These commands operate on the data directory and should be run with the
serving process stopped:

```sh
nix run . -- verify --data-dir ./cache
nix run . -- doctor --data-dir ./cache --json
nix run . -- reconcile --data-dir ./cache --verify-hashes
nix run . -- list-orphans --data-dir ./cache --verify-hashes
nix run . -- stats --url http://127.0.0.1:5000
nix run . -- gc --data-dir ./cache --target-bytes 100000000000 --dry-run --json
nix run . -- gc --data-dir ./cache --target-bytes 100000000000 --apply --json
nix run . -- delete --data-dir ./cache --store-hash STORE_HASH
```

### Runtime statistics

The read-authorized `GET /metrics` endpoint exposes runtime statistics in
Prometheus text format; `HEAD /metrics` returns the same headers without a
body. Both `/metrics` and `/main/metrics` are uncached. The CLI prints the same
Prometheus exposition:

```sh
curl -fsS https://cache.example/metrics
narjar stats --url https://cache.example
```

Cache lookup hit, miss, and failure counters are separate by method and object
type; failures are not silently counted as misses. Hit ratios are request-
weighted successful lookups divided by successful lookups plus genuine misses.
They are exposed as `narjar_cache_lookup_hit_ratio`; failure ratios have a
separate `narjar_cache_lookup_failure_ratio`. GET and HEAD, NAR and narinfo,
remain separate. A ratio with no eligible observations is omitted rather than
reported as zero or NaN. This is not a build-success rate, a unique-object
ratio, saved bandwidth, or the local Nix store's hit rate.

Lifetime byte counters reset when the daemon restarts. Upload declared bytes
are the HTTP body length; received bytes count body bytes actually read. Served
artifact bytes count successful socket writes/sendfile returns for NAR and
narinfo bodies, including partial bytes before a failed transfer; they exclude
headers, HEAD bodies, and the statistics endpoints. They describe bytes
accepted by the local socket, not proof that a remote application consumed
them. HTTP response counters retain each supported status code (including
200, 206, 404, and 416); connection outcomes separately report admission,
queue rejection, malformed requests, timeouts, and disconnects. Recent rates
use the actual coverage of a five-second sampler with a
fixed five-minute history; startup reports a window only after it has enough
samples.

`narjar_nar_range_requests_total{method,outcome}` counts full, partial,
unsatisfiable, and invalid Range decisions for existing NARs, with GET and
HEAD kept separate. A 416 is also visible in the HTTP status series.

Process RSS/CPU, thread count, and bounded open-file-descriptor count are Linux
process observations. They describe Narjar itself, not cache hits or storage
capacity. Filesystem capacity and staging headroom are sampled from the cache's
open directory and reservation budget; headroom is an estimate, not an
admission promise.

`narjar_readiness{reason=...}` distinguishes available, low-space, no-inodes,
read-only, and probe-failed states. Population totals are not scanned on a
request. Enable the delayed background population walk with a 60-second first
delay and a 15-minute default interval (optionally pass another interval in
seconds):

```sh
narjar serve --data-dir /var/lib/narjar --stats-inventory-interval-seconds
```

These series use different accounting bases; do not compare or substitute
them as though they measured the same quantity. Byte-valued metrics report
bytes, and time-valued metrics report seconds; unit conversion for display
belongs in the dashboard:

| Observation | What it measures | What it does not mean |
| --- | --- | --- |
| `narjar_process_start_time_seconds`, `narjar_process_uptime_seconds` | This process's start and elapsed runtime | Host boot, service deployment time, or a restart counter |
| `narjar_http_*_bytes_total` | Lifetime HTTP body bytes consumed or accepted by socket writes in this process epoch | Cache population size, payload bytes physically stored, or proof the peer application consumed a send |
| `narjar_nar_upload_validated_logical_bytes_total` | Logical NAR size for completed uploads whose encoded and decoded hash/size checks succeeded | Parsed NAR grammar or signature validation |
| `narjar_nar_upload_committed_logical_bytes_total{outcome}` | Logical NAR size at durable canonical upload publication, separated into created and identical outcomes | Encoded wire bytes or a disk-usage delta |
| `narjar_cache_population_apparent_bytes{kind="raw"}` | Lengths of observed raw payload pathnames, each stored pathname counted once | Sum of narinfo claims, allocated blocks, or ZFS-charged space |
| `narjar_cache_population_narinfo_claimed_nar_bytes` | Structurally valid `NarSize` claims summed per store path | Unique content bytes; paths sharing content contribute repeatedly |
| `narjar_cache_population_logical_nar_bytes` (chunked backend) | Logical sizes in distinct valid canonical chunk manifests | Chunk/manifest file lengths or flat-backend data |
| `narjar_storage_capacity_bytes{kind}` | Destination filesystem total and currently available capacity from `statvfs` | Bytes used by Narjar alone |
| `narjar_cache_population_apparent_bytes{kind=...}` | Observed file lengths in the cache namespace | Filesystem block allocation; hard links, sparse files, snapshots, and metadata change allocation |
| `narjar_zfs_bytes{kind,state}` | Values reported for the explicitly configured ZFS dataset, including logical, referenced, snapshot, child, and reservation accounting | A cache-only physical total if that dataset contains unrelated data |

ZFS's reported `compressratio` is distinct from a derived logical-to-used
quotient. No current population metric measures allocated blocks; use the dated
ZFS sample for filesystem-level usage when configured.

The population report exposes its start and completion timestamps, elapsed
duration, entries scanned, ignored/disappeared entries, errors, and a bounded
quality classification (`complete`, `changed_during_scan`, `entry_errors`, or
`failed`).
`narjar_cache_population_refresh_failed` distinguishes an incomplete/failed
refresh from an initial not-yet-run scan. An incomplete or failed refresh
preserves the previous complete sample and marks it stale instead of replacing
it with partial totals. Narinfo filenames and contents are structurally parsed;
this population pass does not verify signatures. Malformed filenames and
malformed contents and unreadable narinfo entries are reported separately from
structurally parsed metadata. It sums apparent file lengths for
narinfo metadata, raw and compressed payloads, chunk files/manifests, ingress
and egress receipts, validation evidence, recovery records, and temporary
files. `narjar_cache_population_narinfo_claimed_nar_bytes` separately sums
structurally valid `NarSize` claims once per store path, so shared content is
counted more than once there; raw-file bytes count stored pathnames instead.
These parsed claims are not signature verification. Chunked logical NAR bytes
are shown separately from manifest/chunk file bytes; chunk-only fields are
absent for the flat backend. This online walk is
not a
point-in-time snapshot, does not hash payload contents, and must not be used to
certify integrity, decide GC, or claim physical ZFS space reclaimed. Before its
first completed scan, and after a failed refresh with no previous result, the
population state is explicitly unavailable.

`GET /metrics` is the Prometheus interface. For a request-weighted narinfo GET
hit ratio, sum the lookup outcomes before dividing rather than averaging
instance ratios:

```promql
sum(rate(narjar_cache_lookup_outcomes_total{object="narinfo",method="GET",outcome="hit"}[5m]))
/
sum(rate(narjar_cache_lookup_outcomes_total{object="narinfo",method="GET",outcome=~"hit|miss"}[5m]))
```

The independent failure rate is available under `outcome="failure"`. Resource
and population samples expose their state and sample age; missing platform
measurements are not represented as healthy zeroes.

The one- and five-minute upload/artifact throughput and process-CPU gauges use
the actual elapsed sample coverage, reported separately from the requested
window. They are absent until there are at least two usable samples. If a
cumulative traffic-byte counter saturates, Narjar reports
`narjar_traffic_byte_counters_overflowed 1` and omits byte-rate estimates
rather than presenting a misleading delta.

Explicit GC, reconcile, structural cleanup, and verify commands persist one
bounded summary per operation type. `/metrics` reports the latest completed
timestamp, mode, outcome, duration, available object counts, inventory classes,
and GC's logical reclaimed-byte total. A start without completion remains a
separate observation; it may be an operation still running or one interrupted
by process failure. GC logical bytes are not physical disk space, and counts
the command did not measure are omitted. Reading `/metrics` never runs GC,
reconcile, or verification.

On NixOS, set `services.narjar.statsInventory = true` to enable the bounded
population sampler; its interval defaults to 900 seconds and can be changed
with `services.narjar.statsInventoryIntervalSeconds`.

Set `services.narjar.statsZfsDataset` to opt into a read-only,
once-per-minute ZFS sample for the dataset mounted at `dataDir`. The collector
checks both the dataset's configured mountpoint and the active mount source,
rejects child datasets, and writes a bounded sample under `/run`; Narjar
exposes physical `used`, logical/reference usage,
compression properties, and sample age through `/metrics`. Compression
algorithms use bounded labels; their numeric levels are a separate gauge, and
unrecognized future settings are grouped as `other`. Without this option,
ZFS-specific series report an unavailable state.

Latency histograms use fixed seconds buckets from 1 ms through 5 minutes plus
`+Inf`. Lookup distributions stop when the object decision is made; NAR and
narinfo delivery distributions include response writing and can therefore
reflect slow clients. Publication and publication-queue wait are separate
operations. Durable publication results separately count newly created,
identical, conflicting, and failed outcomes. For example, estimate the 95th
percentile narinfo lookup latency:

```promql
histogram_quantile(0.95, sum by (le) (rate(narjar_operation_duration_seconds_bucket{operation="narinfo_lookup"}[5m])))
```

`narjar_nar_upload_validated_logical_bytes_total` counts logical NAR bytes
after a complete upload passes encoded and decoded hash/size checks; it does
not establish NAR grammar or signature validity.
`narjar_nar_upload_committed_logical_bytes_total{outcome}` counts those logical
bytes when the canonical payload is durably created or found identical. These
storage-boundary counts are distinct from encoded HTTP body bytes and do not
infer input-to-output encoding conversions.
Failed response transfers are classified by `narjar_response_transfer_failures_total`
with fixed `timeout`, `disconnected`, and `other` labels; partial body bytes
remain included in the artifact-output counter.

The storage layer also reports compressed derivative reuse, generation,
generation failures, repair, and callers coalesced behind active generation.
For the chunked backend, chunk and byte counters distinguish newly stored
content from reused content. These are actual storage outcomes, reset with the
daemon; they are not inferred from HTTP status codes.

`gc` is a dry run unless `--apply` is supplied. It uses logical file lengths
for accounting; compression, snapshots, reflinks, and sparse extents are
filesystem concerns outside that accounting. `delete` removes publication
metadata but deliberately leaves the NAR object; garbage collection handles
reclaiming unreferenced objects.

`doctor` is a bounded, non-mutating preflight. It reports the fixed layout,
permissions and ownership, destination capacity/inodes, read-only state, mount
device observations, and whether the DATA lease is currently available. Its
JSON output has schema version `1`; unavailable platform facts are reported as
unavailable rather than inferred.

For the stopped-service backup and restore procedure, including trust and
credential handling, see [the backup and restore runbook](docs/operations.md#backup-and-restore).

## Build and test

devenv supplies the pinned Rust toolchain and native development tools. Nix
continues to supply vendored Cargo dependencies and the reproducible build and
test outputs:

```sh
devenv shell
cargo fmt --all -- --check
cargo test --locked
nix flake check -L --no-update-lock-file
```

The same checks are available as devenv tasks:

```sh
devenv tasks run check:fmt
devenv tasks run check:clippy
devenv tasks run check:test
devenv tasks run check:nextest
devenv tasks run check:shell
devenv tasks run check:flake
```

The fuzz helpers use the pinned nightly compiler:

```sh
devenv tasks run fuzz:list           # list available fuzz targets
devenv tasks run fuzz:build          # build nar_decode with the pinned nightly
```

Start a loopback development server with a disposable cache using
`devenv processes up narjar`. It listens on `127.0.0.1:5000` and stores its
data under `.devenv/state`.

Useful flake outputs on supported systems:

```sh
nix build .#narjar
nix run .
nix run .#provenance
nix run .#nix-e2e
nix run .#oci-e2e
nix build .#packages.x86_64-linux.narjar-static
nix build .#packages.x86_64-linux.narjar-oci
```

The supported development systems are `x86_64-linux` and `aarch64-darwin`.
The static Linux and OCI outputs are available on `x86_64-linux`.

## Profile the server

On Linux, the development shell includes `perf`, Inferno, and heaptrack. The
profiling script first cleans both Cargo targets, rebuilds with debug info and
frame pointers, populates at least 20 GiB of real Nix store paths, then copies
the largest stored NAR up to 1 GiB into `/dev/shm` for CPU and heap capture so
the filesystem is not the read bottleneck. Use `--hot-nar-max-gib` to change
that tmpfs NAR ceiling:

```sh
devenv shell -- scripts/profile.sh --size-gib 20 --seconds 60
```

The script prints an output directory such as `/tmp/narjar-profile.XXXXXX`.
It contains the raw and rendered profiles, heaptrack report, build log,
workload logs, metadata, and `commands.log`, which records the commands that
were actually executed while omitting generated token values. The HTTP
workload uses `compression=none` and sends `Accept-Encoding: identity`.

The copied analysis helpers can summarize the results without opening a GUI:

```sh
devenv shell -- scripts/parse_flamegraph \
  /tmp/narjar-profile.XXXXXX/flamegraph.svg summary
devenv shell -- scripts/parse_perfdata \
  /tmp/narjar-profile.XXXXXX/perf.data --max-stack 128
```

## Repository layout

- `src/` — the CLI, HTTP server, storage, authentication, and Nix push client
- `tests/` — Rust, CLI, and real-Nix end-to-end coverage
- `nix/` — NixOS module and VM test
- `scripts/` — profiling and profile-analysis tools
- `docs/` — protocol, architecture, operations, verification, and risk notes

Keep changes reproducible: use the pinned development toolchain, keep
`Cargo.lock`, `flake.lock`, and `devenv.lock` committed, and sign commits with
GPG.
