# Changelog

## 0.2.0 — Unreleased

### Added

- **Online garbage collection.** `narjar gc --online` collects through the
  running daemon without stopping the service. Recent uploads and advertised
  objects receive a ten-minute grace period, protected roots retain their
  dependencies, and collection defers if publication changes the inventory.
  Age-based retention accepts periods such as `--delete-older-than 7d`.
  ([#52](https://github.com/mjc/narjar/pull/52))
- **Bounded retention policies.** Optional last-use eviction, per-pass deletion
  limits, measured filesystem free-space targets, and bounded contention retries
  are available through the CLI and NixOS module. Scheduled collection remains
  disabled by default.
  ([#57](https://github.com/mjc/narjar/pull/57))
- **Native-store HTTP serving.** `serve --serve-source native-store` serves raw
  NARs directly from an existing local Nix store. It reuses trusted signatures
  or signs with a configured key, installs durable GC roots before advertising
  paths, and supports GET, HEAD, and byte ranges without storing another payload
  copy. Advertisements and leases survive restart; uploads are rejected.
  ([#58](https://github.com/mjc/narjar/pull/58))
- **Read-through caching.** `serve --serve-source read-through` provides a local
  read-only cache backed by one trusted upstream. Raw, XZ, and Zstd downloads are
  verified and durably stored before narinfo is returned. Concurrent fills share
  download work, retention leases protect advertised objects across restarts,
  and upstream outages or invalid downloads become local misses. Nix can build
  locally with `fallback = false` when the required build recipes and inputs
  are available. The NixOS module can configure the loopback substituter and its
  metadata cache lifetimes.
  ([#59](https://github.com/mjc/narjar/pull/59))
- **Additional operational metrics.** Build and metrics-schema identity, active
  workers, artifact request rates, full/range delivery timings, online collection
  outcomes, and access-hint recording are exposed through `/metrics`. Capacity
  sampling runs in the background and retains the last successful observation
  when a refresh fails.
  ([#54](https://github.com/mjc/narjar/pull/54),
  [#57](https://github.com/mjc/narjar/pull/57))

### Fixed

- Native push uses separate DNS/connect and network inactivity timeouts.
  Transfers can exceed the configured timeout while making progress; stalled
  reads and writes still time out.
  ([#56](https://github.com/mjc/narjar/pull/56))
- Handled publication conflicts, identical retries, and failed uploads clean up
  staging and journals when rollback is durable. Failed cleanup or uncertain
  publication retains recovery evidence.
  ([#56](https://github.com/mjc/narjar/pull/56))
- Publication-duration metrics now report the correct count, sum, and maximum.
  Metrics scrapes no longer probe filesystem readiness, and the ZFS collector
  passes its property list correctly.
  ([#54](https://github.com/mjc/narjar/pull/54))
- Filesystem capacity measurements are separate from write-admission policy.
  Admission still rejects read-only filesystems, insufficient bytes, and measured
  inode exhaustion; absent inode measurements are represented explicitly.
  ([e163583](https://github.com/mjc/narjar/commit/e16358331548557941119cd5817d86148699016e))
- Idle HTTP connections use operating-system readiness events while preserving
  admission limits, idle deadlines, and socket ownership during worker handoff.
  ([8cc6566](https://github.com/mjc/narjar/commit/8cc65663fcacda702c4c37a68381797ef23b8b86),
  [d4f5ba6](https://github.com/mjc/narjar/commit/d4f5ba6fe39042ee0b1d9eb74225a1553a125d42))
- macOS warning-denying builds and real-Nix GC checks handle platform-specific
  helpers and canonical temporary-store paths correctly.
  ([#53](https://github.com/mjc/narjar/pull/53))
- Release preparation verifies the correct Cargo archive and uploads GitHub
  assets before publishing the release. Publication retries compare existing
  artifacts instead of replacing published assets.
  ([860f39e](https://github.com/mjc/narjar/commit/860f39e17f2f3abd10f34ef85050cbe7af06d89a),
  [bab7aa5](https://github.com/mjc/narjar/commit/bab7aa5c758a2bd07df239f1f242c1ec68ce2084))
- The locked rustls dependency is updated to 0.23.46 to address the dependency
  advisory gate. ([#52](https://github.com/mjc/narjar/pull/52))

### Compatibility and operation

- Application internals now compile only into the CLI. The unsupported
  `narjar::__private` module has been removed; the supported Rust library remains
  `nar`, `nar_encode`, and `object`, including use with
  `default-features = false`.
  ([#55](https://github.com/mjc/narjar/pull/55))
- Flat-cache serving remains the default. Native-store and read-through modes
  are opt-in and serve raw NARs. Chunked storage remains Linux-only; the CLI
  supports Linux and macOS, with WSL required on Windows.
- Native-store and read-through leases must cover clients' positive narinfo
  cache lifetimes and delayed payload requests. Active leases can keep a cache
  above its collection target. See the [operations guide](docs/operations.md)
  before configuring shorter leases or enabling retention.
- Rust 1.98 or later is still required.

## 0.1.0

Initial release: parallel native closure uploads, signed narinfo validation,
upload tokens, raw/XZ/Zstd transfer support, flat and optional chunked storage,
Prometheus metrics, offline verification and garbage collection, a NixOS module,
and a static Linux binary.

[Release and artifacts](https://github.com/mjc/narjar/releases/tag/v0.1.0)
