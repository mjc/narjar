# Architecture

Narjar stores cache state in a private filesystem directory. The server needs
neither Nix nor an external database. The push client reads its local Nix
store and SQLite metadata database; native-store HTTP serving is not
implemented.

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
