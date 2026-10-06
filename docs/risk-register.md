# Operational risks and verification boundaries

This register describes the implemented filesystem cache. Current release
checks are in the [release procedure](release.md#validate-the-candidate);
historical design proposals and benchmark thresholds are not release gates.

## Transport compatibility and authentication

Nix probe counts, ordering, retries, and negative caching can change between
client versions. The server validates each request independently, publishes
NAR data before narinfo, and handles identical retries without replacing
immutable content. Linux CI runs the locked real-Nix app for both flat and
chunked storage; [historical protocol captures](evidence/nix-http-protocol.md)
describe their recorded clients. Neither is evidence for every Nix version.
Use `--refresh` after a prior miss when immediate visibility is required.

A write token grants transport access, not signing authority. Narinfo requires
a signature from a configured producer key. The server holds public keys and
token hashes; the push client holds private signing material. A compromised
trusted producer can authorize malicious content even when every hash and
signature is valid. Revoke its key and quarantine affected publications.
Rotate keys with overlap because consumers can retain signed metadata.
See [credential operations](operations.md#cli).

Narjar serves plain HTTP. Use a TLS reverse proxy for remote access, restrict
direct access to a trusted network, disable PUT buffering, preserve
Content-Length and Authorization, align limits and timeouts, and redact
credentials from logs. Loopback end-to-end CI does not validate a deployment's
certificate, buffering, or timeout configuration. Client HTTPS support does
not provide TLS termination for the server.

## Untrusted input and bounded resources

Strict route grammars and once-only decoding prevent request paths from
escaping DATA. Metadata validation binds the route, store path, encoded
representation, raw NAR identity, references, and producer signature before
narinfo becomes visible. A valid signature does not prove NAR grammar;
consumer Nix parses and verifies the imported NAR. The separate library codecs
have their own [semantic-input threat model](nar-threat-model.md).

Upload limits cover encoded bytes, decoded NAR bytes, and compressed-decoder
memory. At most `workers` decoders run concurrently, so the configured decoder
memory budget is `workers × maxDecoderMemoryBytes`, in addition to other
process allocations. Bounded admission, stream timeouts, staging reservations,
and a free-space reserve reduce resource exhaustion; they do not guarantee
availability under hostile traffic or prevent external disk consumption.
Use proxy connection/rate limits and monitor capacity and admission failures.

## Publication, corruption, and recovery

Publication uses destination-local staging, content checks, file and directory
synchronization, and no-replace final links. Flat storage publishes a canonical
raw NAR; chunked storage synchronizes chunks before publishing its authoritative
manifest. Narinfo is the store-path visibility marker. Transactions and recovery
markers distinguish interrupted work from completed publications.

Fault tests and interrupted-upload CI cover process-level failures. They do
not establish power-loss behavior on every filesystem or device. Chunked
storage requires Linux `syncfs` and is rejected on macOS; APFS-specific flat
crash durability also remains unverified. Follow the
[filesystem capability contract](filesystem-capability-adr.md).

Ordinary availability checks do not detect every same-size out-of-band
mutation. Run offline `verify` or `reconcile --verify-hashes` for full content
verification. Quarantine affected narinfos before repairing payloads. Preserve
shared chunks and manifests together; a chunk directory alone is not a NAR.
See [recovery](operations.md#restart-matrix).

## Maintenance and capacity accounting

Serving and maintenance require the same exclusive DATA lease. Delete and GC
operate offline, remove and sync narinfo first, and retain canonical data while
any publication still references it. GC retains protected roots and their
transitive references; chunked GC follows live manifests to shared chunks.
No HTTP delete endpoint or resident GC worker is provided.

Backups must preserve the selected layout, canonical objects, manifests/chunks,
published metadata, policy files, and recovery records. Stop serving for the
documented backup procedure, then verify a restored root before using it.
GC reports logical file lengths, which do not predict physical bytes freed
under compression, CoW, or snapshots. Measure destination capacity separately.
See [backup and restore](operations.md#backup-and-restore).

## Packaging and performance claims

The flake builds Linux and Apple Silicon packages; CI tests Darwin flat storage
and real Nix transfers on Linux. Static ELF and runtime closure checks reject
dynamic linkage or prohibited runtime dependencies. The generated module
scripts are inspected at build time without import-from-derivation; module
evaluation alone does not execute a systemd service. Native-store serving is
disabled by the module until that HTTP path is implemented.

Those checks do not prove separate-host runtime behavior without Nix or boot a
NixOS VM. Dependency advisories are checked using the
[advisory gate](dependency-advisories.md). Performance, RSS, physical-space
savings, and filesystem-specific recovery claims require evidence for the
actual workload and deployment. Archived benchmarks supply measurements for
their recorded conditions, not general guarantees or release requirements.
