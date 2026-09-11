# Gitoxide storage audit

This is the NARJ-86 feasibility audit for the pinned gitoxide graph. It is a
capability audit, not a production dependency proposal. The disposable probe
used for the API checks lived outside this repository at
`/tmp/narjar-gix-probe`.

## Versions and evidence

The probe used one coherent graph: `gix-odb 0.84.0`, `gix-pack 0.74.2`,
`gix-object 0.64.1`, `gix-hash 0.26.2`, and `gix-features 0.49.1`. `cargo
check` and `cargo run` both passed against those exact versions. The run
streamed a small blob through the loose writer and read it back through the
loose store. The probe also type-checked the pack writer signature with an
explicit allocation limit.

Primary references:

- [gitoxide crate status](https://github.com/GitoxideLabs/gitoxide/blob/main/crate-status.md)
- [`gix-object` 0.64.1 API](https://docs.rs/gix-object/0.64.1/gix_object/)
- [`gix-odb` API](https://docs.rs/gix-odb/latest/gix_odb/)
- [`gix-pack` API](https://docs.rs/gix-pack/latest/gix_pack/)
- [Gitoxide `write_blob_stream` implementation](https://github.com/GitoxideLabs/gitoxide/blob/main/gix/src/repository/object.rs)
- [Gitoxide malformed-pack advisory](https://github.com/GitoxideLabs/gitoxide/security/advisories/GHSA-x494-mj8g-cj27)

The crate-status page is the source of truth for whether a component is
production-ready; docs.rs is used for the exact public API and the local crate
source was inspected for buffering, limits, and publication behavior.

## Capability matrix

| Required operation | Result | Evidence and consequence |
| --- | --- | --- |
| Loose-object streaming write | Supported with constraints | `gix_odb::loose::Store::write_stream` accepts `&mut dyn Read`, hashes while writing a compressed temporary file, and persists the result. Narjar would still own directory creation, file modes, collision policy, and durability. |
| Loose-object streaming read | Missing at the loose-store API | `try_find` writes the complete decompressed object into a caller-provided `Vec<u8>`. `try_header` avoids the object body but there is no body-to-`Write` or body-stream API in this store. |
| High-level blob streaming | Reject for Narjar | Gitoxide's high-level `Repository::write_blob_stream` reads the stream into a reusable in-memory buffer before writing. That is the opposite of Narjar's bounded upload path. |
| Loose lookup and SHA-1/SHA-256 | Supported with constraints | The store is parameterized by `gix_hash::Kind`; the feature graph must enable the desired hash implementations. The object format is Git's loose format, not Nix's semantic NAR identity. |
| Pack lookup and reconstruction | Supported with constraints | `gix-pack` exposes indexed lookup, full/delta decoding, pack caches, and explicit `alloc_limit_bytes` controls. A caller must set limits and decide whether caches are enabled. |
| Pack/index creation | Supported with constraints | `Bundle::write_to_directory` consumes a pack stream and generates pack/index files, using temporary files. It is a pack ingest/indexing operation, not a NAR-specific object store. The caller owns final durability and publication. |
| Fresh delta selection | Missing for this use case | The pack writer preserves the input pack and can resolve thin-pack bases; its compression option applies to bases added while completing a thin pack. It does not provide a NAR-aware “choose deltas across these loose objects” policy. That policy would be custom work. |
| Concurrent lookup | Supported with constraints | The ODB has handles and optional pack/object caches. The cache layer stores decoded objects in `Vec`s and is opt-in; cache-disabled behavior must be selected explicitly and measured. This does not supply Narjar's publication/recovery synchronization. |
| Corruption and resource limits | Supported with constraints | Pack and delta paths expose allocation limits for untrusted metadata and decoded entries. This is per-allocation protection, not a process-wide RSS or total-work budget. Hostile-pack tests remain required before any adoption. |
| Atomic publication and fsync | Custom work required | The loose writer uses `tempfile::Persist`; the pack writer stages temporary files and returns paths. Neither gives Narjar's required file-sync, directory-sync, no-replace publication, recovery marker, or startup inventory contract. |
| Interrupted maintenance/recovery | Custom work required | Pack/index generation has interruption and temporary-file handling, but recovery policy and durable inventory are application responsibilities. No Narjar recovery proof was obtained from these crates. |
| Static-musl and unsafe/transitive surface | Not audited here | The exact API probe was a native debug build. Static packaging, transitive unsafe inventory, and reachable advisories need a separate build/security gate and are not claimed by this document. |

## Recommendation

Reject gitoxide as Narjar's production storage backend for now. It can be a
useful isolated prototype for reading existing Git objects or validating pack
input, but the missing bounded streaming read, lack of a NAR-specific delta
selection policy, and application-owned durability/recovery surface leave the
core cache path custom either way. Adding the crates would also introduce a
large maintenance and advisory-tracking surface for a storage format Narjar
does not serve.

If a future prototype is authorized, it should use only narrow `gix-odb` and
`gix-pack` APIs, disable both caches initially, set explicit allocation limits,
keep Git repository/network features out of the graph, and wrap every generated
file in Narjar-owned sync/rename/recovery logic. It must first pass the
adversarial pack, concurrent lookup, RSS, and static-musl probes listed in
NARJ-86. No production dependency change is made by this audit.
