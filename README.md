# narjar

A filesystem-backed HTTP binary cache for Nix, written in Rust.

Narjar stores Nix build outputs and serves them through the binary cache
protocol. It includes a cache server, a parallel closure uploader, and
commands for verification and garbage collection. The server runs without a
Nix installation or a database.

Uploads and downloads support uncompressed NARs, Zstd, and XZ. Upload
compression, storage layout, and download compression are configured separately.

## Installation

To build from source, install Rust 1.98 or later, a C toolchain, pkg-config, and
the SQLite development libraries:

```sh
git clone https://github.com/mjc/narjar.git
cd narjar
cargo install --locked --path .
```

The repository also provides a Nix package, a NixOS module, and a Linux OCI image.
To run the CLI with Nix:

```sh
nix run github:mjc/narjar -- --help
```

## Create a cache

Run these commands in a working directory where you want to keep the cache and
its credentials. The signing key stays outside the cache directory.

```sh
umask 077

narjar init --data-dir ./cache

narjar key generate \
  --name local-producer \
  --secret-key-file ./producer.sec \
  --public-key-file ./producer.pub

cp ./producer.pub ./cache/trusted-public-keys

narjar token create \
  --data-dir ./cache \
  --scope write \
  --name local > ./write.token

printf 'machine 127.0.0.1 login narjar password %s\n' \
  "$(cat ./write.token)" > ./narjar.netrc

narjar serve --data-dir ./cache --listen 127.0.0.1:5000
```

Reads are public by default; writes require a token. Use `init --private-read`
and create a read-scoped token to require authentication for reads too.

Narjar speaks HTTP. For remote access, run it behind a TLS reverse proxy and
use an HTTPS cache URL. The server verifies metadata with the public keys in
`trusted-public-keys`; the uploader holds the signing key.

## Push a closure

In another terminal, from the same working directory, build a store path and
upload it with its dependencies:

```sh
store_path=$(nix build --no-link --print-out-paths nixpkgs#hello)

narjar push \
  --to http://127.0.0.1:5000 \
  --netrc-file ./narjar.netrc \
  --insecure-http \
  --signing-key-file ./producer.sec \
  --compression zstd \
  --jobs 8 \
  "$store_path"
```

`push` reads the local Nix store database, walks the dependency closure, and
uploads dependencies before their dependents. Independent paths upload in
parallel, up to `--jobs`. It serializes NARs and signs their metadata directly,
without invoking Nix subprocesses.

The command takes concrete `/nix/store/...` paths. It needs read access to the
store and its SQLite metadata database, plus permission to create temporary
GC roots. The Nix command in this example builds the input path.

Netrc credentials are sent over HTTPS unless `--insecure-http` is supplied.
That flag is needed for the local HTTP example above. Upload requests have a
30-second timeout by default; change it with `--timeout-seconds`.

Matching paths already at the destination are skipped. `--refresh` forces
uploads. Conflicting metadata fails the push; `--ignore-conflicts` skips those
paths and continues.

### Skip paths available from another cache

Use `--trusted-upstream URL` and
`--trusted-upstream-key 'URL#NAME:BASE64'` to check another cache before
uploading. Both flags can be repeated.

An upstream hit requires a trusted signature and matching store path, NAR hash,
size, and references. Narjar checks metadata only; it does not fetch or copy
the upstream payload. Consumers must have access to that upstream as a
substituter. Failed checks fall back to uploading the local path.
`--refresh` bypasses upstream checks.

## Use the cache from Nix

Add the cache URL and the contents of `producer.pub` to the consuming
machine's `nix.conf`:

```ini
extra-substituters = https://cache.example
extra-trusted-public-keys = local-producer:BASE64_PUBLIC_KEY
```

Replace the URL and public key with your own values. For the local example,
use `http://127.0.0.1:5000`. Apply the configuration to the Nix daemon when
using a multi-user installation.

Nix verifies the producer's signatures. A write token grants upload access;
it does not replace signature verification.

## Storage and compression

The default `flat` backend stores each canonical, uncompressed NAR as a file.
The optional `chunked` backend splits NARs into content-defined chunks and
deduplicates them across objects. Choose it with
`init --storage-backend chunked`, and pass the same backend to serving and
maintenance commands.

`push --compression` controls the uploaded representation.
`serve --egress-compression` controls the representation advertised to Nix
clients. Both accept `none`, `zstd`, and `xz`, and default to `none`.

Compressed downloads are stored as reusable derivatives of the canonical NAR.
Narjar rewrites the narinfo transport fields to describe the served bytes while
preserving the signed NAR identity. Payloads are committed before the metadata
that references them.

Server defaults:

| Option | Default |
| --- | --- |
| `--listen` | `127.0.0.1:5000` |
| `--workers` | `8` |
| `--max-in-flight` | `64` |
| `--max-nar-bytes` | 16 GiB |
| `--min-free-bytes` | 1 GiB |
| `--egress-compression` | `none` |
| `--storage-backend` | `flat` |

Run `narjar serve --help` for all options and their `NARJAR_*` environment
variables.

## Monitoring

`GET /metrics` returns Prometheus text. It includes cache hits, misses and
failures; request and transfer counts; throughput and latency; process memory
and CPU; storage capacity; and publication and maintenance results.

```sh
curl -fsS http://127.0.0.1:5000/metrics
narjar stats --url http://127.0.0.1:5000
```

Hit ratios are hits divided by hits plus misses, separated by object type and
HTTP method. Failures are counted separately. Process counters reset on restart.

Cache population scans are optional. Enable them with
`serve --stats-inventory-interval-seconds 900`. Metrics requests read the latest
sample; they do not trigger a scan. Private caches require read credentials
for metrics.

See the [metrics reference](https://github.com/mjc/narjar/blob/main/docs/operations.md#observability)
for metric definitions, sample freshness, and accounting rules.

## Maintenance

Stop the serving process before running commands that inspect or modify its
data directory:

```sh
narjar doctor --data-dir ./cache --json
narjar verify --data-dir ./cache
narjar reconcile --data-dir ./cache --verify-hashes

narjar gc --data-dir ./cache --target-bytes 100000000000 --dry-run --json
narjar gc --data-dir ./cache --target-bytes 100000000000 --apply --json
```

Garbage collection defaults to a dry run. Its byte totals use logical file
lengths; filesystem compression and snapshots affect actual reclaimed space.
`delete --store-hash HASH` removes a path's metadata; GC reclaims unreferenced
payloads.

See [operations](https://github.com/mjc/narjar/blob/main/docs/operations.md)
for retention, recovery, and backup procedures.

## Development

The devenv shell supplies the pinned Rust toolchain and development tools:

```sh
devenv shell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo nextest run --locked
nix flake check -L --no-update-lock-file
```

The library exports NAR encoding and decoding, narinfo, and storage APIs.
Generate API documentation with `cargo doc --no-deps --open`.

Further documentation:

- [Architecture](https://github.com/mjc/narjar/blob/main/docs/architecture.md)
- [Binary cache protocol](https://github.com/mjc/narjar/blob/main/docs/protocol-v0.1.md)
- [Filesystem requirements](https://github.com/mjc/narjar/blob/main/docs/filesystem-capability-adr.md)
- [NixOS module](https://github.com/mjc/narjar/blob/main/nix/module.nix)
- [Benchmark tools](https://github.com/mjc/narjar/blob/main/docs/benchmark-scripts.md)
- [CPU and heap profiling](https://github.com/mjc/narjar/blob/main/scripts/profile.sh)
