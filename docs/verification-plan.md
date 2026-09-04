# Narjar v0.1 dependency, test, and benchmark plan

Status: design-gate draft for NARJ-15, NARJ-16, and NARJ-19.

## Runtime dependency budget

The initial allowed set is deliberately small:

| Crate | Purpose | Why standard library is insufficient | Rejected alternative |
| --- | --- | --- | --- |
| std::net + httparse | Blocking HTTP/1.1 listener and streamed request/response bodies | Correct HTTP parsing and connection handling are security boundaries; httparse supplies zero-copy request syntax validation | tokio/hyper/axum add an async stack not needed for a bounded worker pool |
| sha2 | Streaming SHA-256 required by Nix hashes and token hashing | Rust std has no cryptographic hash | OpenSSL/ring add native/TLS surface |
| ed25519-dalek | Verify Nix narinfo signatures | Rust std has no Ed25519 | Server signing and private-key custody |
| data-encoding | Strict Base64 and custom Nix32 encoding | Hand-rolled codecs are protocol/security risk | General serialization framework |
| getrandom | Cryptographic token and temporary-name entropy | Rust 1.85 std has no stable OS RNG API | Full rand distribution framework |
| subtle | Constant-time fixed-size token-hash comparison | Optimizers can defeat a handwritten compare | Password-KDF stack for already-random 256-bit tokens |
| signal-hook | Portable SIGINT/SIGTERM flag registration | Rust std exposes no stable signal handler API | Async runtime or control-socket framework |
| libc | Nonblocking advisory lock on `DATA/lock` | Rust 1.85 has no stable file-lock API | Stale PID files or a larger portability crate |
| lzma-rust2 | Streaming pure-Rust XZ decode/encode | Rust std has no XZ codec; Nix default binary-cache uploads use `.nar.xz` | liblzma/xz2 add a native C library boundary; sevenzip is a different container |

Candidate metadata captured with `cargo info` on 2026-08-31. These are review
candidates, not loose semver ranges: implementation pins the selected exact
versions in Cargo.lock and upgrades only after the same dependency gates.

| Crate | Candidate | License | Declared MSRV | Features and static/audit impact |
| --- | --- | --- | ---: | --- |
| httparse | 1.10.1 | MIT OR Apache-2.0 | undeclared; prove on 1.85 | default features off with `std`; zero-copy HTTP/1.x syntax parser; no listener, TLS, date, logging, or body buffering |
| sha2 | 0.11.0 | MIT OR Apache-2.0 | 1.85 | default features off unless required; pure RustCrypto digest stack; no native library |
| ed25519-dalek | 3.0.0 | BSD-3-Clause | 1.85 | verification only; default features off, with `fast` admitted only by measurement; curve/signature transitive audit is the main crypto surface |
| data-encoding | 2.11.1 | MIT | 1.48 | `std` only; pure Rust; custom Nix32 alphabet configured locally |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | 1.85 | no optional features; direct OS entropy; no `rand` distribution stack |
| subtle | 2.6.1 | BSD-3-Clause | undeclared; prove on 1.85 | default features off; fixed-size comparison only; pure Rust |
| signal-hook | 0.4.4 | MIT OR Apache-2.0 | 1.66 | default features off; flag registration only; no iterator/channel or C helper |
| libc | 0.2.189 | MIT OR Apache-2.0 | 1.65 | default features off; one documented `flock` call; already present through signal-hook |

The project MSRV is Rust 1.85, matching the pinned shell. An undeclared upstream
MSRV is accepted only after an explicit 1.85 build. Every candidate is
permissively licensed and compatible with a musl static build when the rejected
native/TLS features remain disabled; the Linux static closure check is the
proof, not this table.

No dependency is approved merely because it is convenient. The implementation
must start with exact versions pinned by Cargo.lock and default features
disabled where practical.

Explicitly rejected for v0.1:

- tokio, hyper, axum, tower, async-trait, futures utility stacks.
- clap, serde, TOML/YAML frameworks, anyhow, thiserror/derive error frameworks.
- tracing subscriber stacks or Prometheus client crates.
- redb, SQLite, rkyv, object-store abstractions.
- zstd/xz/brotli/flate codecs.
- rustls/native-tls/OpenSSL and ACME clients.
- NAR semantic parser crates or libnix bindings.
- General thread-pool crates; a fixed std thread set and bounded channel suffice.

A rejected crate may be reconsidered only with a focused benchmark/security
argument and a risk-register update.

## Dependency gates

Every dependency change must pass:

1. cargo tree with duplicate/version/feature review.
2. cargo deny or equivalent license, advisory, source, and ban policy.
3. cargo machete/udeps-equivalent unused dependency check where supported.
4. musl static build and static ELF proof.
5. Runtime closure check excluding Nix, compiler, shell, TLS, DB, and codec
   libraries not explicitly accepted.
6. Release binary size and settled idle RSS comparison.
7. No build script, proc macro, unsafe code, or native library without an
   explicit review note.

unsafe_code remains denied in Narjar source. Unsafe inside dependencies is part
of dependency review, not silently waived.

## Test layers

### Domain unit tests

Run on every change with cargo nextest:

- Nix32/Base64 valid and invalid vectors.
- StoreHash, FileHash, StorePath, NarUrl, ByteCount, and token-hash domain types.
- Strict route parsing and exactly-once percent decoding.
- Narinfo singleton fields, references, unknown fields, numeric bounds, and
  canonical fingerprint.
- Real cache.nixos.org signature positive vector.
- Wrong key name/material, changed hash/size/path/reference negative vectors.
- Range parser full, open-ended, suffix, empty, overflow, multiple, and
  unsatisfiable cases.
- Auth mode capability matrix and constant-time fixed-size comparison API.
- Status/header/body contract for every route classification.

### Generated/property tests

Use proptest only as a dev dependency if table-driven generation becomes
unreadable. Required properties:

- No arbitrary byte request path escapes DATA or maps to a different route after
  re-encoding.
- Accepted identifier render/parse round-trips exactly.
- Invalid alphabet/length identifiers never reach filesystem construction.
- Narinfo parse never panics for arbitrary bounded bytes.
- Range parsing never overflows and returned ranges are within file length.
- Duplicate/concurrent immutable publication never overwrites.
- Memory retained by a streaming upload is independent of body size.

### Fuzz targets

cargo-fuzz targets are release gates, not normal runtime dependencies:

- route bytes and percent encoding;
- narinfo bytes and duplicate fields;
- Basic Authorization decoding;
- Range header;
- nix-cache-info parser used at startup.

Seed corpora include raw observed requests, real narinfos, truncated inputs,
overlong numbers, Unicode confusables, slash encodings, NUL, and duplicate
headers. Each target must complete the recorded CI duration with no panic,
hang, excessive allocation, or path escape.

### Filesystem and fault tests

A temporary same-filesystem fixture exercises each failure boundary:

| Injection point | Required final state |
| --- | --- |
| before temp create | no temp, no final |
| mid-body EOF | removable temp only |
| body over limit | removable temp only |
| hash/size mismatch | removable temp only |
| temp file sync failure | no final |
| no-replace conflict, identical | existing final unchanged, idempotent success |
| no-replace conflict, different | existing final unchanged, 409 |
| parent directory sync failure | no 201; reconcile-safe state |
| crash after NAR publication | orphan NAR, no narinfo visibility |
| crash during narinfo temp | published NAR plus temp only |
| crash after narinfo link, before response | durable pair; retry is identical success |
| disk full | no new narinfo; bounded error and cleanup attempt |

No general storage abstraction is added solely for fault injection. Introduce
the smallest test hook at the exact publication boundary if OS-level fixtures
cannot trigger an error deterministically.

### Real socket conformance

Start the actual binary on 127.0.0.1 with a temporary DATA directory and assert
raw HTTP:

- all GET/HEAD/PUT success and error statuses;
- Content-Length, Content-Type, Allow, WWW-Authenticate, cache, range, and
  nosniff headers;
- connection close between sequence steps;
- partial PUT socket close and exact retry;
- slow body at worker/concurrency limit;
- valid/invalid/suffix/open range reads;
- no Authorization or token bytes in captured logs;
- published files and modes after shutdown/restart.

### Real Nix end-to-end

The E2E test must use an independent Nix store destination, not file:// as a
signature-verification proxy.

Required sequence:

1. Generate producer key and trusted public key in a temporary directory.
2. Build or add a unique store path.
3. Sign recursively with the producer key.
4. Push with stock nix copy, compression=none, and regular-file netrc.
5. Pull through Narjar into an independent store.
6. Prove bytes/path and Nix verification succeed.
7. Repeat with an untrusted signing key and require publication refusal.
8. Repeat after a recorded 404; require --refresh for immediate visibility.
9. Repeat through the TLS reverse proxy with buffering disabled.
10. Run from the built static Linux binary on a host with no server Nix runtime
    dependency.

Tests record Nix/curl/system versions and sanitized request traces.

## Reconciliation and restore tests

Fixture states include:

- valid pair;
- orphan NAR;
- narinfo missing NAR;
- wrong FileHash/FileSize;
- corrupt object bytes;
- stale and young temporary files;
- unknown file and invalid filename;
- interrupted token/public-key file replacement.

GC coverage additionally uses deterministic 0, 100, 1,000, and 10,000
published-path fixtures. It records full-inventory, dry-run, and apply wall
time plus peak RSS at 10,000 paths. The serving path must retain no
population-sized index; the offline command may materialize its bounded
inventory. GC fixtures cover protected closures, shared NAR reference counts,
age-gated orphans, dry-run/apply candidate identity, impossible targets, and
every narinfo/NAR directory-sync failure boundary.

Reconcile is read-only by default and emits a stable report. Any cleanup
requires an explicit subcommand and age threshold. A restore drill copies a
backup into an empty DATA directory, runs reconcile, then completes real-Nix
substitution.

## Benchmark method

Matched controls run on the same host, filesystem, CPU governor/power state,
kernel, Nix closure, payload corpus, reverse-proxy choice, and sample order.
Narjar is compared to the current pinned bincache revision and, where useful,
a static web server over file:// output.

Use at least 15 measured repetitions after warm-up; report median, p95, min/max,
and raw samples. Randomize candidate order. Distinguish cold page cache from
warm page cache. Record commit, tool versions, and exact command.

## Benchmark scenarios and gates

| Scenario | Measurement | v0.1 gate |
| --- | --- | --- |
| Empty startup to listening socket | wall time | median <100 ms; p95 <150 ms |
| 10k narinfos startup | wall time | no material increase; no full scan |
| Idle after 30 s | RSS/PSS | settled RSS <30 MiB |
| 1 MiB/100 MiB/1 GiB PUT | peak RSS | increase bounded by concurrency buffer, not body size |
| PUT | throughput and CPU seconds | report versus direct disk and bincache |
| Full GET, warm/cold | throughput, CPU, latency | no avoidable full-file buffering |
| 1 MiB range from 1 GiB file | latency and bytes read | bounded to requested range |
| 1/8/32/limit concurrency | throughput, p95, RSS, FDs | stable until admission cap |
| 404 narinfo | requests/s and p95 | no allocation/RSS growth |
| Restart after orphan/temp corpus | startup and correctness | no accidental publication |
| Static package | binary and closure bytes | report; no dynamic ELF interpreter |

Greenfield decision gate:

- Narjar must beat bincache materially on at least two core premises among
  startup, idle RSS, dependency/closure size, operational state, and upload CPU;
  and
- it must not regress required native protocol/trust behavior; and
- the benefit must come from the chosen deletions, not disabled safety checks.

If that gate fails, stop greenfield work and adopt/contribute upstream.

## Commands

The repository shell is entered through direnv or Nix:

~~~sh
direnv allow
direnv exec . cargo nextest run
direnv exec . cargo clippy --all-targets --all-features -- -D warnings
direnv exec . cargo fmt --all --check
direnv exec . nix flake check --all-systems --accept-flake-config
~~~

Linux static artifact proof additionally builds packages.x86_64-linux.narjar-static
and runs the static-ELF check on a reachable Linux builder.
