# Changelog

## 0.2.0 — 2026-10-20

### Added

- Native Windows support for standalone flat caches on local NTFS, including
  setup, authenticated uploads, serving, verification, and online GC. Windows
  releases include an x86-64 MSVC binary; the Visual C++ runtime is required.
  `push` and native Nix-store serving remain Linux/macOS-only.
- Online garbage collection through the running daemon, with a ten-minute grace
  period and protected roots. Retention supports `--delete-older-than 7d`,
  last-use eviction, free-space targets, per-pass limits, and contention retries.
  These policies are also available for scheduled collection in the NixOS module.
- Native-store serving: serve raw NARs from an existing local Nix store without
  keeping another payload copy. Durable GC roots protect advertised paths;
  metadata can reuse trusted signatures or use a configured signing key.
- Read-through caching from one trusted upstream. Downloads are verified and
  stored before advertisement; concurrent requests share fills. Unavailable or
  invalid upstream objects become cache misses so Nix can build locally.
- Metrics for build identity, request rates, full/range delivery timings, online
  GC, and access tracking. Filesystem capacity is sampled in the background.

### Fixed

- Push timeouts now measure network inactivity rather than total request time,
  allowing long transfers while they continue making progress.
- Completed rollbacks clean up staging files and publication journals. Failed
  cleanup and uncertain publication retain the evidence needed for recovery.
- Corrected publication timing and ZFS metrics, filesystem-capacity reporting,
  and macOS build and GC checks. TLS verification dependencies were updated.
- Idle connections use operating-system readiness events without retaining a
  worker per connection. Process locks retain the validated directory identity.
- Release publication verifies the packaged crate and uploads assets before
  publishing GitHub releases. Retries compare already-published artifacts.

### Compatibility and operation

- Removed the unsupported `narjar::__private` module. The Rust library exposes
  `nar`, `nar_encode`, and `object`, including with `default-features = false`.
- Flat-cache serving remains the default. Native-store and read-through modes
  are opt-in and serve raw NARs. Chunked storage remains Linux-only.
- Native-store and read-through leases must cover clients' positive narinfo
  cache lifetimes and delayed payload requests. Active leases can keep a cache
  above its collection target. See the [operations guide](docs/operations.md)
  before configuring shorter leases or enabling retention.

[Full changes since 0.1.0](https://github.com/mjc/narjar/compare/v0.1.0...v0.2.0)

## 0.1.0

Initial release: parallel native closure uploads, signed narinfo validation,
upload tokens, raw/XZ/Zstd transfer support, flat and optional chunked storage,
Prometheus metrics, offline verification and garbage collection, a NixOS module,
and a static Linux binary.

[Release and artifacts](https://github.com/mjc/narjar/releases/tag/v0.1.0)
