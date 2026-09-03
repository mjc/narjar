# Narjar v0.1 red-team design review

Status: approved on 2026-08-31 for a conditional thin implementation slice.

## Verdict

Approve the flat-filesystem, client-signed, compression=none-or-xz architecture and
its v0.1 protocol contract.

This is not approval for an unconstrained new binary-cache project. bincache
already occupies the obvious small-Rust-server design point. Narjar may proceed
only because the frozen profile removes the database, recompression, server
signing key, background workers, startup index, online GC, and native Nix
runtime. NARJ-30 must measure that differential against pinned bincache after
the real-Nix thin slice. If it is not material, stop Narjar and adopt bincache.

The design gate is complete. Remaining items below are implementation proof
obligations, not unanswered architecture questions.

## Review basis and NARJ-1 deliverables

| Required output | Approved artifact |
| --- | --- |
| 1. Prior-art comparison | [prior-art.md](./prior-art.md) |
| 2. Current-Nix HTTP trace | [nix-http-protocol.md](./evidence/nix-http-protocol.md) and sanitized trace fixtures under [evidence](./evidence/) |
| 3. Assumptions and unresolved questions | Protocol classifications in [protocol-v0.1.md](./protocol-v0.1.md) and explicit evidence boundaries in the trace report |
| 4. Trust model | Client-signed decision in [architecture.md](./architecture.md) and risks R4/R5 in [risk-register.md](./risk-register.md) |
| 5. Native-store versus flat-store architecture | Architecture and read/write flow diagrams in [architecture.md](./architecture.md) |
| 6. On-disk layout | Deterministic layout and permissions in [architecture.md](./architecture.md) and [operations.md](./operations.md) |
| 7. Upload/publication state machines | Byte flow in [architecture.md](./architecture.md) and durable/restart matrices in [operations.md](./operations.md) |
| 8. Threat model | Sixteen owned risks in [risk-register.md](./risk-register.md) |
| 9. Dependency table | Role/alternative and version/license/MSRV/static-impact tables in [verification-plan.md](./verification-plan.md) |
| 10. Testable milestones | NARJ-21 through NARJ-30 and the invariant matrix in [verification-plan.md](./verification-plan.md) |
| 11. Benchmark plan | Matched controls, corpus, repetitions, thresholds, and raw-sample policy in [verification-plan.md](./verification-plan.md) |
| 12. Risk register | [risk-register.md](./risk-register.md) |
| 13. v0.1 acceptance criteria | This review, [protocol-v0.1.md](./protocol-v0.1.md), and [verification-plan.md](./verification-plan.md) |
| 14. Explicit non-goals | [architecture.md](./architecture.md) and [protocol-v0.1.md](./protocol-v0.1.md) |
| 15. Alternative red team | [prior-art.md](./prior-art.md) and the objections below |

## Existential challenge

### file:// plus a static web server

This remains the correct answer for a cache produced out of band. It does not
provide native HTTP PUT ingestion, per-request write auth, streamed validation,
immutable conflict handling, or a durable narinfo-last publication boundary.
Narjar should not replace it for read-only deployments.

### Harmonia plus SSH writes

Harmonia is a mature choice when a native Nix store and Nix-aware server are
acceptable. SSH-mediated writes and a server Nix installation violate Narjar's
ordinary HTTP producer, no-server-Nix, flat-backup, and single-binary
constraints. Adopt Harmonia if those constraints are relaxed.

### Kasha

Kasha is the closest no-Nix/no-database/client-signing reference and validates
the basic technology choices. Its S3 support, manifests, workers, GC, and
deployment model are more machinery than this profile permits. Extracting only
its serving core would still create a maintenance fork; reuse algorithms and
test vectors, not a partial fork.

### bincache

bincache is the strongest objection. A generic lightweight Rust Nix HTTP cache
does not justify Narjar. The conditional answer is a measured profile with no
database, recompression, server key, workers, or startup index. NARJ-30 is a
hard continuation gate, not an optional benchmark.

### Celler and Attic

Both solve broader fleet, metadata, retention, and multi-user concerns. Their
extra state is valuable for those products and contrary to this single-tenant
profile. Narjar must not grow their features one by one; needing them is a
migration signal.

## Adversarial findings and resolutions

### Native-store/object-store confusion

Resolved. The daemon never opens, imports into, or serves a native /nix/store.
It maps strict HTTP identities directly to immutable files. Producer and
consumer Nix installations are outside its process and data directory.

### Assumed PUT order

Resolved by two real socket traces and upstream source. Nix uploads the NAR
before narinfo. Narinfo is the only store-path visibility marker. Narjar remains
safe if requests are reordered: narinfo publication fails until its exact
durable NAR exists.

### Signature authority

Resolved. A write token permits transport only. Every narinfo requires a
signature over the canonical Nix fingerprint from a configured producer public
key. The server stores no private signing key and cannot mint trusted paths.
Public-key rotation overlaps old and new keys until retained narinfos no longer
need the old key.

### Narinfo forgery and unsigned fields

Resolved for current Nix fields. StorePath, NarHash, NarSize, and References are
signature-bound. URL, FileHash, FileSize, and compression=none are checked
against the exact durable bytes. Deriver and CA use current Nix grammar and
cannot replace the required signature; inconsistent CA cannot make a different
store path content-addressed. Unknown fields are rejected so future unsigned
semantics do not silently enter the trust boundary.

### Semantic NAR validity and decompression bombs

Resolved by scope. Narjar accepts raw bytes and `.nar.xz`, but only streams XZ
decompression to validate the raw hash and size; it does not recompress or
semantically parse a NAR. Hashing/counting is O(1) memory and decompressed output
is capped. "Validated" means route, size, hash, metadata, and producer signature
validated, not that Narjar duplicated Nix's NAR importer. A trusted signer can
authorize malformed bytes, but consumer Nix still parses and rejects them.
Adding a second NAR parser would enlarge, not reduce, the attack surface.

### Partial visibility and durability

Resolved. NAR and narinfo use same-filesystem temporaries, file sync,
no-replace final publication, and parent-directory sync. NAR is durable before
narinfo validation begins. A 201 is returned only after the named file and its
directory entry are durable. A crash may leave an orphan NAR or temporary, but
never a reader-visible partial pair.

### Duplicate and concurrent PUTs

Resolved. Immutable destination identity is the lock granularity. Writers use
separate temporaries and one no-replace winner. A loser compares the winner:
identical bytes are idempotent 200; disagreement is 409. There is no unbounded
per-key mutex map.

### Traversal and route ambiguity

Resolved. Routes accept exact segment counts and fixed Nix32 alphabets/lengths.
Decoded separators, dot segments, duplicate slashes, suffixes, query-driven
identity, and arbitrary filesystem paths are rejected before lookup. User input
never becomes a joined path.

### Ranges, deletion, and read races

Resolved. Only one validated byte range is supported. Readers open the final
immutable file before responding. v0.1 deletion is offline, requires the serve
lock, removes/syncs narinfo first, and leaves NAR bytes. There is no online GC
or range/delete race.

### Slow clients, floods, descriptors, and memory

Resolved with an explicit boundary. A fixed worker set, bounded admission queue,
Content-Length, object limits, fixed buffers, and reverse-proxy connection/body
timeouts bound process resources. tiny_http does not justify pretending to
offer an in-process socket deadline it cannot enforce. Public internet
deployment without the required proxy is unsupported.

### Disk full, EIO, corruption, and crash recovery

Resolved. Admission checks size and free-space reserve but treats them as
guidance. ENOSPC is 507; sync/EIO is 500; no failure claims publication.
Read-time failure of a published pair is an integrity error, not a silent miss.
Startup does not mutate. Offline reconcile/verify classifies every final/temp
state and may perform full hash verification.

### Key deletion and credential compromise

Resolved operationally. Tokens are random, hashed at rest, created with
one-time stdout output, independently scoped, and atomically revoked. Token
compromise cannot sign. Removing a still-required public key makes readiness or
verification fail and requires restoration/quarantine; it never causes server
re-signing.

### Proxy buffering and TLS

Resolved as a deployment contract with pending executable proof. TLS, client
certificate/CA policy, header/body progress timeouts, and buffering-disabled
streaming belong to the trusted reverse proxy. NARJ-17/NARJ-18 must run through
the production-style proxy and verify that large bodies are not buffered.

### Startup and RSS claims

Not accepted on architecture alone. Direct route lookup and no boot scan make
the targets plausible, not proven. NARJ-30 must report matched startup/RSS
against bincache. Failure stops greenfield continuation unless the product
premise is explicitly revised.

### GC safety and backup/restore

Resolved by exclusion. There is no automatic/online GC, access-time retention,
or pin database. Offline deletion only removes publication metadata. Backups
copy immutable finals excluding temporaries and run verify. Future offline
mark-and-sweep can consume existing References plus a reserved roots/manifests
directory without changing current identities.

### Dependency and framework pressure

Resolved by a seven-crate candidate ceiling and gates. No async runtime, web
framework, TLS stack, codec, DB, serialization/config/CLI/logging/metrics
framework, general thread pool, or NAR parser is approved. Standard library
code handles the small fixed formats. New dependencies require a recorded
decision and static-closure/audit proof.

## Frozen v0.1 scope

Required:

- Public-read/private-write and optional private-read modes.
- GET/HEAD nix-cache-info, narinfo, and NAR routes.
- One byte range for NAR reads.
- Native Nix PUT of nix-cache-info, compression=none NAR, then narinfo.
- Client-signed narinfo verification and immutable durable publication.
- Bounded workers, health/readiness/metrics, safe token operations.
- Offline reconcile, verify, logical delete, and orphan listing.
- Static x86_64-linux packaging, Nix package/module, systemd, and OCI artifact.
- Real-socket and real-Nix push/substitute/trust acceptance.

Explicit non-goals:

- Native store serving or a server Nix installation.
- Compression, recompression, decompression, semantic NAR parsing.
- Server-side signing/private-key custody.
- Realisations, listings, build logs, mass-query writes, mirrors.
- Database, S3, Redis, queues, workers, multi-tenancy, quotas, UI.
- Online GC/deletion, retention, pins, payload deduplication.
- Native TLS, ACME, socket activation, TOML, control API.
- Multi-range responses and conditional-write extensions.

## Exact implementation gate

1. Complete NARJ-29: the direnv/Nix shell is authoritative and cached, Darwin
   checks pass, and a reachable Linux builder proves the static x86_64 artifact
   and ELF closure. Environment evaluation alone is not artifact proof.
2. RED: add failing protocol/domain/storage tests directly from the frozen
   vectors. The red commit contains tests and fixtures, not production behavior.
3. GREEN: implement the smallest vertical slice that makes those tests pass:
   strict identities, compression=none hashing, durable immutable publication,
   narinfo verification, and GET/HEAD/PUT over a real socket.
4. REFACTOR: encode already-proven invariants in narrow types such as StoreHash,
   FileHash, PublishedNar, and VerifiedNarInfo; do not add speculative traits or
   extension points.
5. Run NARJ-17 and NARJ-18 through stock Nix and the production-style proxy.
6. Run NARJ-30 against pinned bincache. Stop and adopt bincache if the material
   simplicity/resource differential is absent.
7. Only after that continuation decision may the broader refactor and operator/
   packaging surface proceed. The broader refactor should delete accidental
   coupling and encode filesystem/publication boundaries, not add layers.

Every implementation commit is GPG-signed. Red, green, invariant refactor, and
broader architectural refactor remain separate behaviorally coherent commits.

## Remaining proof obligations

- NARJ-29: Linux static artifact/ELF proof; current configured Tina builder is
  unreachable, while direnv and all local/all-system evaluation checks pass.
- NARJ-17/NARJ-18: real-socket, proxy, stock-Nix, wrong-key, interrupted,
  refusal, and substitution proof.
- NARJ-30: matched bincache continuation decision.
- NARJ-27: final systemd/NixOS/OCI and no-server-Nix runtime proof.

These obligations block release or continuation at the stated gates. None
changes the approved protocol, authority, or publication model.
