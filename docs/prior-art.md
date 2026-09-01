# Nix binary-cache prior art

Status: NARJ-3 design-gate draft. Sources were checked on 2026-09-01.
This is a fit analysis for Narjar v0.1, not a popularity ranking.

## Decision summary

A greenfield Narjar that merely offers a small Rust HTTP binary cache should
not exist: [bincache](https://github.com/wyattgill9/bincache) already implements
that product shape, including native nix copy PUTs, netrc auth, server signing,
atomic storage, ranges, metrics, reconciliation, real-socket conformance tests,
and a real-Nix signature-gated end-to-end test.

There is still a narrower design worth evaluating: a static, single-tenant,
filesystem-only cache that stores compression=none uploads byte-for-byte,
requires client-signed narinfo, holds no signing key, has no database, no
recompression, no online GC, and no background workers. That profile is a
strict subset between bincache and [Kasha](https://github.com/Zebradil/kasha).
Narjar should proceed only if the architecture gate accepts those deletions and
an adversarial comparison shows that adopting bincache or trimming Kasha would
cost more and preserve fewer invariants.

## Matrix

| System | Write path | Read path | Storage/index | Trust model | Operations | Fit for Narjar |
| --- | --- | --- | --- | --- | --- | --- |
| Nix file:// | Native nix copy | Native local binary cache | Flat filesystem layout, no daemon | Client or destination secret-key settings | Local filesystem only | Protocol/layout oracle; not remotely shared |
| Nix s3:// | Native nix copy through AWS SDK | S3 API or public HTTP | Flat bucket objects | AWS credentials plus Nix signatures | Cloud IAM and bucket lifecycle | Avoids a server but violates local-filesystem and no-cloud goals |
| Harmonia | Primarily serves an existing native Nix store | HTTP substituter, ranges, listings, logs | Native /nix/store and Nix DB | Optional server signing | Nix installation/store required | Too coupled to Nix on the server |
| Attic | Custom client/API upload | HTTP substituter | Database plus chunked object storage | Multi-tenant tokens, managed signing | GC, deduplication, remote storage | Far beyond single-tenant v0.1 |
| Celler | Attic-compatible client/API | HTTP substituter | Attic-derived DB/object architecture | Multi-tenant auth and managed signing | GC, observability, OIDC roadmap | Same mismatch as Attic |
| Kasha | Native signed nix copy plus generation manifests | HTTP substituter; eager S3/upstream mirroring | Flat files, boot scan, no DB | Client signing; trusted-key verification | Workers, manifests, S3 mirror, timed GC | Strongest no-DB reference, but its distributed lifecycle is out of scope |
| bincache | Native compression=none nix copy | HTTP substituter with ranges | Content-addressed files plus redb | Token writes; server discards client signatures and re-signs | Metrics, reconcile, delete, rotate; no online GC | Closest complete implementation; default adopt-before-build candidate |
| niks3 | Dedicated push service/CLI and direct S3 publication | Public S3/CDN HTTP | S3 objects plus service-side reference tracking | Cloud credentials and server-side signing | Presigned uploads and GC | Good split read/write model; violates local-only constraint |

## Nix's built-in stores

The [local binary cache store](https://nix.dev/manual/nix/2.35/store/types/local-binary-cache-store.html)
is the simplest authoritative layout: file:// reads and writes a flat binary
cache in a directory and creates it when absent. It proves no database is
required for protocol correctness.

The [S3 binary cache store](https://nix.dev/manual/nix/2.35/store/types/s3-binary-cache-store)
uses the same binary-cache idioms with AWS credential discovery and object
operations. Public reads can bypass the S3 store implementation and use HTTP.
This is attractive when object storage is already an accepted dependency; it
is not a substitute for an offline, filesystem-backed appliance.

## Harmonia

[Harmonia](https://github.com/nix-community/harmonia) is a Rust HTTP
substituter over an existing /nix/store. It supports ranges, build logs, NAR
listings, zstd, TLS, and metrics. Its native-store dependency solves a
different problem: exposing a machine's store. Narjar's server must not need
Nix, its database, or native store registration.

Reusable lessons:

- Range behavior and static-file response headers.
- Streaming compression/read paths.
- Reverse-proxy and NixOS deployment patterns.

Rejected scope:

- Depending on /nix/store or the Nix database.
- Serving arbitrary store contents or build logs in v0.1.

## Attic and Celler

[Attic](https://github.com/zhaofengli/attic) targets multi-tenant remote
caching, global deduplication, chunking, database-backed metadata, managed
signing, and garbage collection. [Celler](https://github.com/celler-cache/celler)
continues that architecture. Their custom client/API and operational footprint
are justified by tenancy, quota, and large shared-cache needs that Narjar
explicitly does not have.

Reusable lessons:

- Upload-session and interrupted-write threat models.
- Separation between immutable payloads and mutable metadata.
- Tenant/auth boundaries to avoid accidentally recreating.

Rejected scope:

- Multi-tenancy, quotas, chunking, global deduplication, DB migrations,
  object-store abstraction, and managed service workflows.

## Kasha

[Kasha](https://github.com/Zebradil/kasha) is a static Rust LAN cache with flat
narinfo/NAR files, no server Nix, no database, client-side signing, and trusted
key verification during ingestion. Those choices closely match the proposed
minimal Narjar trust and storage profile.

Kasha then adds a larger product: generation manifests, S3-compatible
mirror-up/down workers, upstream population, local and remote retention, an
OCI image, a NixOS consumer module, and status tracking. Narjar v0.1 excludes
all of that.

Adopt-or-trim question:

- If Kasha's HTTP ingestion and flat-store modules are separable, contributing
  a minimal serve-only mode is preferable to cloning them.
- If the worker/manifest lifecycle is structurally inseparable, Narjar may
  justify a smaller implementation, but the architecture review must record
  exact coupling evidence.

## bincache

[bincache](https://github.com/wyattgill9/bincache) is the direct competitor.
It requires compression=none uploads, validates the raw NAR, recompresses to
zstd, stores content-addressed payloads, indexes records in redb, signs every
narinfo with a server key, and serves resumable reads. Its tests already cover
the levels planned for Narjar: handler tests, a real socket, and a real Nix
push/pull with negative signature proof.

Its extra mechanisms are not automatically defects:

- redb enables indexed metadata, shared payload accounting, rotation, and
  reconciliation.
- Server signing means build nodes need write credentials but not trusted
  signing keys.
- Recompression provides one canonical read codec regardless of upload.

They are nevertheless the exact complexity Narjar proposes to avoid. A valid
Narjar differential would be:

- Files are the index; startup validation is a bounded narinfo scan.
- The server never owns a signing key and never rewrites signatures.
- compression=none remains compression=none; no CPU-heavy recompression.
- No io_uring-specific runtime path, sharding, redb, rkyv, metrics dependency,
  key rotation, or online deletion in v0.1.

Before implementation, benchmark and fault-model that differential against
bincache. If the simpler profile cannot beat its idle RSS/startup/operability
targets materially, adopt bincache.

## niks3

[niks3](https://github.com/Mic92/niks3) separates a private write service from
a direct public S3/CDN read path and includes reference tracking and garbage
collection. It is a useful proof that read availability need not depend on the
write service. Its S3 and cloud-IAM assumptions are outside Narjar's local
single-binary boundary.

## Red-team conclusion

The strongest objection is not technical risk; it is duplication. Two current
Rust projects already cover almost all requested behavior:

- bincache covers the small native HTTP cache.
- Kasha covers the no-Nix, no-DB, client-signing flat cache plus much more.

Therefore NARJ-3 cannot approve "build Narjar as planned." It can approve only
one of these outcomes:

1. Adopt bincache and contribute any missing constraints upstream.
2. Add or extract a serve-only profile from Kasha.
3. Build Narjar as the demonstrably smaller no-DB/no-key/no-recompression
   profile, with a written differential and matched measurements.

The architecture gate must pick one before a Rust server red test is added.
