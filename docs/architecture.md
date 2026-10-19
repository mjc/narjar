# Architecture

Narjar stores cache state in a private filesystem directory. The server needs
neither Nix nor an external database in its default cache mode. The push client
and optional native-store server source read the existing Nix store and its
SQLite metadata database.

## Native-store source

Source selection happens at startup. Native mode uses the same binary-cache
routes and authorization as cache mode, but rejects uploads. It produces raw
NARs directly from leased store paths rather than staging a second payload.

A narinfo lookup verifies a reusable signature or signs with a configured key,
acquires the exact path's durable GC-root lease, then re-reads its logical claims
from a fresh database snapshot. The response is emitted only if those claims
still match. Startup does not retain a read transaction that hides later Nix
registrations or blocks database writers.

Raw NAR delivery retains the lease and active-delivery guard through canonical
serialization and EOF identity checking. Range delivery verifies the remainder
before completing the response. HEAD uses the declared length without starting
serialization. Lease recovery runs before readiness; bounded expiry cleanup
continues while serving. Shutdown leaves unexpired roots in place for clients
with cached metadata.

Trusted advertisements durably associate a NAR hash with its rooted store path.
Payload requests use that bounded record lookup rather than an unindexed
database hash query. Unknown or expired associations return a miss without
leasing an unsigned path. Per-lease association records and the raw-hash index
are serialized with lease mutation; cleanup retains an index owned by another
still-live path with identical NAR contents.

## Read-through source

The read-through cache downloads from one configured HTTP upstream. On a local
miss, it verifies the narinfo signature, downloads the named NAR, checks its hash
and size, and stores it uncompressed. It returns the rewritten narinfo only after
the NAR, metadata and retention record have been written and synced to disk.
This prevents Nix from being told a NAR is available before its download finishes.

Concurrent requests for the same store path or uncompressed NAR share a download.
The number of downloads, waiting requests and cached failures is limited. An
upstream failure returns a local cache miss; a local hit does not contact the
upstream. This mode needs no local Nix store or build daemon and does not queue
uploads to the upstream.

Each retention record is a lease: a time before which GC must not delete the
metadata or NAR. Reads extend that time before returning metadata. Storage
coordinates these updates with GC, including offline GC after a restart. GC
keeps publications whose records are missing and returns an error for invalid
records rather than deleting potentially protected data.

## Identities and representations

A logical NAR has an uncompressed SHA-256 hash and byte count. Its raw, XZ,
and Zstd transport representations have their own file hashes and lengths.
Upload compression, canonical storage, and download compression are separate
choices.

Uploads are streamed, hashed, and counted. Compressed input is decoded
directly into canonical staging while its encoded identity is checked.
Narinfo signatures cover the store path, logical NAR identity, and references,
not the selected transport. Publication binds those signed claims to stored
content and projects consistent URL, Compression, FileHash, and FileSize
fields for the served representation.

The server checks byte identity, not NAR grammar. Consumers parse the NAR
while importing it. The public library codecs provide separate bounded NAR
parsing and encoding.

## Data layout

`init --storage-backend flat|chunked` fixes the backend for a data directory.
Flat is the default. Chunked storage is Linux-only; flat also works on macOS.
There is no migration or mixed-layout fallback.

~~~text
DATA/
  .narjar-layout                 immutable backend descriptor
  .narjar-clean / .narjar-recovery
  .narjar-transactions/          publication journal
  nar/
    .tmp/                       payload staging
    <file-hash>.nar[.zst|.xz]    flat raw files and compressed derivatives
  .narjar-manifests/             chunked canonical manifests
  .narjar-chunks/                shared raw chunks, sharded by hash
  .narjar-ingress/               compressed upload-to-raw receipts
  .narjar-egress/                raw-to-compressed download receipts
  .narjar-advertisements/        keep-until times for read-through metadata and NARs
  .narjar-control/gc.sock        private daemon maintenance socket
  .tmp/                         metadata and receipt staging
  <store-hash>.narinfo
  nix-cache-info
  trusted-public-keys
  auth/
    read.tokens
    write.tokens
  lock
~~~

Chunked manifests preserve the exact original NAR byte stream, not an
unpacked filesystem tree. A manifest is required data; chunks alone cannot
reconstruct an object. Compressed derivatives are generated from either
canonical backend and retained for reuse.

An ingress receipt binds the accepted compressed hash, codec, and size to the
measured raw identity. An egress receipt binds a raw identity and codec to
one exact compressed hash and size. Recovery retains useful egress receipts
when derivatives disappear or become corrupt. Regeneration must reproduce
the recorded identity rather than silently selecting new bytes.

## Publication and recovery

Request and publication queues are bounded. Streaming and decoding occur
outside destination commit locks. A lock covers final publication and the
directory synchronization needed before another operation can bind to it.
A separate raw-identity/codec lock coalesces compressed derivative generation.

Canonical content becomes durable before the receipt or narinfo that names
it. Narinfo is the store-path publication marker. Identical immutable PUTs
converge; conflicting content does not overwrite the destination.
Verified repair of server-generated derivatives is a separate atomic
replacement operation, not a relaxation of uploaded-object immutability.

Temporary resources and publication transitions are recorded durably.
Startup validates the fixed layout; a recovery-marked cache also checks trusted
published references before serving. This availability scan checks types,
sizes, manifests, and chunk presence, not every payload hash. Full content
verification is an offline command.

Offline maintenance and serving share an exclusive process lock. Online GC
uses the daemon's storage owner through a bounded private Unix socket.
Publication capabilities invalidate an unlocked collection snapshot when a
mutation begins. Deletion requires a current snapshot and no active mutation.
Recent upload and metadata-advertisement protection retains substitution
dependencies; lazy chunked readers retain their backing chunks.

Delete and GC remove
and sync narinfo before reclaiming content. Shared files and chunks remain
while any retained publication references them. Crashes may leave orphan
data, which does not publish a store path.

The [filesystem contract](filesystem-capability-adr.md) specifies the required
synchronization and repair operations. [Operations](operations.md) covers
credentials, recovery, maintenance, and deployment; the
[HTTP protocol](protocol-v0.1.md) specifies the wire interface.
