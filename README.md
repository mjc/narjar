# narjar

A filesystem-backed HTTP binary cache for Nix, written in Rust with low memory usage.

Run your own binary cache and manage cached data from the command line.
The server runs without a Nix installation or a database. Use `narjar push`
with your existing Nix installation to upload store paths and their dependencies.
Uploads and downloads support uncompressed NARs, Zstd, and XZ.

## Installation

Install Rust 1.98 or later, a C toolchain, pkg-config, and the SQLite development
libraries, then install Narjar:

```sh
cargo install --locked narjar
```

To install from a source checkout:

```sh
git clone https://github.com/mjc/narjar.git
cd narjar
cargo install --locked --path .
```

The CLI supports Linux and macOS. On Windows, run it under WSL.

Nix packages are available for x86_64 Linux and Apple Silicon macOS, with a
NixOS module and a Linux OCI image. Use flat storage on macOS; chunked storage
is Linux-only. To run with Nix:

```sh
nix run github:mjc/narjar -- --help
```

## Create a cache

`narjar setup` creates a cache, signing keys, and upload credentials, then prints
the commands to start the server and upload a store path.
The data and credentials directories must not already exist; their parent
directories must exist.

```sh
narjar setup \
  --data-dir ./cache \
  --credentials-dir ./credentials \
  --cache-url http://127.0.0.1:5000 \
  --listen 127.0.0.1:5000
```

Run the server command printed by setup. Setup does not start it for you.
In a terminal, it asks before creating files; use `--yes` with explicit options
in scripts. Without options, it uses `./narjar-data`, `./narjar-credentials`,
`http://127.0.0.1:5000`, and `127.0.0.1:5000`.

The public key is installed in the cache's `trusted-public-keys` file. The
private key (`producer.sec`), tokens, and netrc file are stored outside the
cache with mode `0600`; the credentials directory has mode `0700`.
Keep the credentials directory out of source control and protect its backups.
Use `--private-read` to create a read token in addition to the write token.
The generated netrc is for uploads; configure consumers with `read.token`.
Setup never prints a secret.

Narjar speaks HTTP. For remote access, run it behind a TLS reverse proxy and
use an HTTPS cache URL.

## Push a closure

In another terminal, from the same working directory, build a store path and
upload it with its dependencies:

```sh
store_path=$(nix build --no-link --print-out-paths nixpkgs#hello)

narjar push \
  --to http://127.0.0.1:5000 \
  --netrc-file ./credentials/narjar.netrc \
  --insecure-http \
  --signing-key-file ./credentials/producer.sec \
  --compression zstd \
  --jobs 8 \
  "$store_path"
```

`push` reads the local Nix store database, walks the dependency closure, and
uploads dependencies before their dependents. Independent paths upload in
parallel, up to `--jobs`. It serializes NARs and signs their metadata directly,
without invoking Nix subprocesses.

The command takes concrete `/nix/store/...` paths. It needs read access to the
store and its SQLite metadata database and keeps temporary GC roots for the
duration of the upload. See [push details](https://github.com/mjc/narjar/blob/main/docs/operations.md#cli)
for native-store access and rooting.

Netrc credentials are sent over HTTPS unless `--insecure-http` is supplied.
That flag is needed for the local HTTP example above. Upload requests have a
30-second timeout by default; change it with `--timeout-seconds`.

Valid publications for the same full store path are skipped, even when a local
build has a different NAR hash, size, or references. The first valid publication
wins. `--refresh` forces uploads but does not replace existing metadata; a
concurrent publication of the same path is also treated as destination-present.
Other immutable conflicts fail the push; `--ignore-conflicts` skips them.

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

## NixOS service

The NixOS module initializes the cache and installs credentials before starting
the server. Secret files must be supplied by a secret manager or another path
outside the Nix store.

```nix
services.narjar = {
  enable = true;
  dataDir = "/var/lib/narjar";
  listen = "0.0.0.0:5000";
  egressCompression = "zstd";
  storageBackend = "flat";
  auth = {
    writeTokens = "/run/secrets/narjar-write.tokens";
    trustedPublicKeys = "/run/secrets/narjar-trusted-public-keys";
  };
};
```

`writeTokens` is a Narjar token-hash file, and `trustedPublicKeys` contains the
cache signing public keys. Set `privateRead = true` and `auth.readTokens` to
require read authentication. The module exposes server limits, metrics, and
scheduled GC options; see the [module options](https://github.com/mjc/narjar/blob/main/nix/module.nix)
and [service configuration](https://github.com/mjc/narjar/blob/main/docs/operations.md#deployment).
Initialization, serving, and collection use the selected `storageBackend`.

## Storage and compression

The default `flat` backend stores each canonical, uncompressed NAR as a file.
The optional `chunked` backend splits NARs into content-defined chunks and
deduplicates them across objects. Choose it with
`init --storage-backend chunked`, and pass the same backend to serving and
maintenance commands. Chunked storage requires Linux; use flat storage on macOS.

Upload and download compression are independent: `push --compression` selects
the upload format, and `serve --egress-compression` selects the download format.
Both accept `none`, `zstd`, and `xz`, and default to `none`.

The server keeps compressed downloads for reuse. Narinfo describes the served
bytes and retains the original NAR signatures. Payloads are committed before
the metadata that references them.

Server defaults:

| Option | Default |
| --- | --- |
| `--listen` | `127.0.0.1:5000` |
| `--workers` | `8` |
| `--max-in-flight` | `64` |
| `--max-nar-bytes` | 16 GiB |
| `--max-encoded-nar-bytes` | 16 GiB |
| `--max-decoder-memory-bytes` | 128 MiB per compressed upload |
| `--min-free-bytes` | 1 GiB |
| `--egress-compression` | `none` |
| `--storage-backend` | `flat` |

Run `narjar serve --help` for all options and their `NARJAR_*` environment
variables.

Compressed uploads are limited by both their encoded size and decoded NAR
size. XZ dictionary memory and Zstd frame windows are checked against
`maxDecoderMemoryBytes` before decoder buffers are allocated. At most `workers`
decoders run at once, with a combined decoder memory limit of
`workers × maxDecoderMemoryBytes`.

A Linux deployment with 32 workers measured 16,676 KiB (16.3 MiB) process RSS
after four days of uptime, using flat storage and uncompressed downloads.
Compressed uploads and concurrent requests can use more memory. Process RSS
excludes the system's filesystem caches.

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

Run the pinned Rust checks through devenv:

```sh
devenv tasks run check:fmt
devenv tasks run check:clippy
devenv tasks run check:test
devenv tasks run check:doc
nix flake check -L --no-update-lock-file
```

Linux CI also runs the locked real-Nix app against both storage backends:

```sh
nix run -L --no-update-lock-file .#nix-e2e -- --storage-backend flat
nix run -L --no-update-lock-file .#nix-e2e -- --storage-backend chunked
```

Run shell commands through `devenv shell -- <command>` unless `DEVENV_ROOT`
already points at the checkout. The end-to-end gates check transfers into
independent Nix stores, signature trust, compression, interrupted uploads,
restart, and offline GC.

Further documentation:

- [Architecture](https://github.com/mjc/narjar/blob/main/docs/architecture.md)
- [Binary cache protocol](https://github.com/mjc/narjar/blob/main/docs/protocol-v0.1.md)
- [Filesystem requirements](https://github.com/mjc/narjar/blob/main/docs/filesystem-capability-adr.md)
- [Release procedure](https://github.com/mjc/narjar/blob/main/docs/release.md)
- [Operational risks](https://github.com/mjc/narjar/blob/main/docs/risk-register.md)
- [NixOS module](https://github.com/mjc/narjar/blob/main/nix/module.nix)
- [Benchmark tools](https://github.com/mjc/narjar/blob/main/docs/benchmark-scripts.md)
- [CPU and heap profiling](https://github.com/mjc/narjar/blob/main/scripts/profile.sh)
