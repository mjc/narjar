# narjar

A filesystem-backed HTTP binary cache for Nix, written in Rust.

Narjar stores Nix build outputs and serves them through the binary cache
protocol. It includes a cache server, a parallel closure uploader, and
commands for verification and garbage collection. The server runs without a
Nix installation or a database.

Uploads and downloads support uncompressed NARs, Zstd, and XZ. Upload
compression, storage layout, and download compression are configured separately.

## Rust API

Narjar's primary product is the CLI. Its supported Rust API is
limited to the NAR streaming decoder (`nar`), canonical event encoder
(`nar_encode`), and typed content identities (`object`). These APIs cover
reading and writing NAR streams; they do not expose cache storage, HTTP server,
authorization, maintenance, or backend lifecycle contracts. Those
implementation modules are hidden under `narjar::__private` for use by the
binary and repository integration tests and are not supported for downstream
consumers. The API may change incompatibly between pre-1.0 minor releases;
patch releases retain compatibility.

## Installation

To build from source, install Rust 1.98 or later, a C toolchain, pkg-config, and
the SQLite development libraries:

```sh
git clone https://github.com/mjc/narjar.git
cd narjar
cargo install --locked --path .
```

The repository also provides a Nix package, a NixOS module, and a Linux OCI image.
The Nix package is provided for x86_64 Linux and Apple Silicon macOS. CI builds
the Darwin package and runs the `narjar` package tests on an Apple Silicon
runner. Chunked storage is Linux-only; use the flat backend on macOS. The
crates.io consumer smoke test runs on x86_64 Linux.
To run the CLI with Nix:

```sh
nix run github:mjc/narjar -- --help
```

After Narjar has been published to crates.io, install a released version with:

```sh
cargo install --locked narjar
```

## Create a cache

Use `narjar setup` for a standalone first run. It initializes the cache,
generates a producer key pair and write token, installs the public key in the
cache, writes a private netrc file, and prints the server and push commands.
The data and credentials directories must not already exist; their parent
directories must exist.

```sh
narjar setup \
  --data-dir ./cache \
  --credentials-dir ./credentials \
  --cache-url http://127.0.0.1:5000 \
  --listen 127.0.0.1:5000
```

In a terminal, setup asks before creating files. Use `--yes` with explicit
options in scripts. Defaults are `./narjar-data`, `./narjar-credentials`,
`http://127.0.0.1:5000`, and `127.0.0.1:5000`. Use `--private-read` to create a
read token as well as the write token. The private signing key, tokens, and
netrc are stored outside the cache directory with mode `0600`; the credentials
directory has mode `0700`. Setup does not start the server.
Keep the credentials directory out of source control and protect its backups.
The generated netrc is for writes; with `--private-read`, configure consumers
with the separate `read.token` value.

Narjar speaks HTTP. For remote access, run it behind a TLS reverse proxy and
use an HTTPS cache URL. The server verifies metadata with the public keys in
`trusted-public-keys`; the uploader holds `producer.sec`. Setup prints the
commands to start the server and push a store path. It never prints a secret.

## NixOS service

The NixOS module initializes the data directory before service startup, installs
credential files from host paths, and configures the server through native
options. Secret files must be supplied by a secret manager or another path
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
require read authentication. The module also exposes `cachePriority`,
`dynamicUser`, `workers`, `maxInFlight`, `maxNarBytes`,
`maxEncodedNarBytes`, `maxDecoderMemoryBytes`, `minFreeBytes`,
`shutdownGraceSeconds`, `ioTimeoutSeconds`, `statsInventory`,
`statsInventoryIntervalSeconds`, `statsFilesystemSample`, and
`statsZfsDataset`. Scheduled collection is configured under `gc` with
`enable`, `schedule`, `maxBytes`, `targetBytes`, `maxAgeSeconds`,
`minAgeSeconds`, and `protectedRoots`. Initialization, serving, and collection
use the selected `storageBackend` consistently.

Use `narjar setup` for standalone installs. For NixOS, the module owns service
lifecycle and data-directory initialization; provide only the credential
files and settings the deployment needs.

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
maintenance commands. Chunked storage is Linux-only because Narjar has not
established its crash-durability ordering on macOS; macOS commands reject this
backend before initialization. The flat backend is the supported macOS storage
layout; APFS-specific crash-durability guarantees remain unverified.

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
| `--max-encoded-nar-bytes` | 16 GiB |
| `--max-decoder-memory-bytes` | 128 MiB per compressed upload |
| `--min-free-bytes` | 1 GiB |
| `--egress-compression` | `none` |
| `--storage-backend` | `flat` |

Run `narjar serve --help` for all options and their `NARJAR_*` environment
variables.

Compressed uploads are limited by both their encoded size and decoded NAR
size. XZ dictionary memory and Zstd frame windows are checked against
`maxDecoderMemoryBytes` before decoder buffers are allocated. Upload decoding
runs on publication workers, so at most `workers` decoders run at once; the
configured worst-case decoder working memory is therefore
`workers × maxDecoderMemoryBytes`.

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

The supported library API exports NAR encoding and decoding plus typed content
identities. Generate API documentation with `cargo doc --no-deps --open`.

Further documentation:

- [Architecture](https://github.com/mjc/narjar/blob/main/docs/architecture.md)
- [Binary cache protocol](https://github.com/mjc/narjar/blob/main/docs/protocol-v0.1.md)
- [Filesystem requirements](https://github.com/mjc/narjar/blob/main/docs/filesystem-capability-adr.md)
- [NixOS module](https://github.com/mjc/narjar/blob/main/nix/module.nix)
- [Benchmark tools](https://github.com/mjc/narjar/blob/main/docs/benchmark-scripts.md)
- [CPU and heap profiling](https://github.com/mjc/narjar/blob/main/scripts/profile.sh)
