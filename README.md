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
