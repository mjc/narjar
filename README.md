# narjar

Narjar is a small, filesystem-backed HTTP binary cache for Nix. It stores NAR
files and signed narinfo files as immutable objects. The server does not need a
Nix installation, database, signing private key, recompression pipeline, or
online garbage collector.

The detailed protocol and operational rules are in [`docs/`](docs/), especially
[`docs/protocol-v0.1.md`](docs/protocol-v0.1.md) and
[`docs/operations.md`](docs/operations.md).

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

Create a netrc containing the write token. The `push` command resolves the
closure, signs it with the supplied key, and invokes native `nix copy` workers:

```sh
printf 'machine 127.0.0.1 login narjar password %s\n' "$(cat ./write.token)" > ./narjar.netrc
chmod 600 ./narjar.netrc

nix run . -- push \
  --to http://127.0.0.1:5000 \
  --netrc-file ./narjar.netrc \
  --signing-key-file ./producer.sec \
  --jobs 8 \
  /nix/store/some-package
```

Use `--refresh` to re-check and re-upload paths already present at the
destination. The server publishes the NAR before its narinfo, and consumers
only see a path after the metadata is durable.

## Inspect and maintain a cache

These commands operate on the data directory and should be run with the
serving process stopped:

```sh
nix run . -- verify --data-dir ./cache
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

## Build and test

Nix supplies the pinned Rust toolchain, vendored Cargo dependencies, and native
tools used by the project:

```sh
nix develop
cargo fmt --all -- --check
cargo test --locked
nix flake check -L --no-update-lock-file
```

Useful flake outputs on supported systems:

```sh
nix build .#narjar
nix run .
nix run .#provenance
nix run .#nix-e2e
nix build .#packages.x86_64-linux.narjar-static
nix build .#packages.x86_64-linux.narjar-oci
```

The supported development systems are `x86_64-linux` and `aarch64-darwin`.
The static Linux and OCI outputs are available on `x86_64-linux`.

## Profile the server

On Linux, the development shell includes `perf`, Inferno, and heaptrack. The
profiling script first cleans both Cargo targets, rebuilds with debug info and
frame pointers, warms an SSD-backed cache with at least 20 GiB of real Nix
store paths, then captures CPU and heap profiles:

```sh
nix develop --command scripts/profile-tina.sh --size-gib 20 --seconds 60
```

The script prints an output directory such as `/tmp/narjar-profile.XXXXXX`.
It contains the raw and rendered profiles, heaptrack report, build log,
workload logs, metadata, and `commands.log`, which records the commands that
were actually executed. The HTTP workload uses `compression=none` and sends
`Accept-Encoding: identity`.

The copied analysis helpers can summarize the results without opening a GUI:

```sh
nix develop --command scripts/parse_flamegraph \
  /tmp/narjar-profile.XXXXXX/flamegraph.svg summary
nix develop --command scripts/parse_perfdata \
  /tmp/narjar-profile.XXXXXX/perf.data --max-stack 128
```

## Repository layout

- `src/` — the CLI, HTTP server, storage, authentication, and Nix push client
- `tests/` — Rust, CLI, and real-Nix end-to-end coverage
- `nix/` — NixOS module and VM test
- `scripts/` — profiling and profile-analysis tools
- `docs/` — protocol, architecture, operations, verification, and risk notes

Keep changes reproducible: use the flake toolchain, keep `Cargo.lock` and
`flake.lock` committed, and sign commits with GPG.
