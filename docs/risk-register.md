# Narjar v0.1 risk register and decision log

Status: NARJ-28 draft for NARJ-20 review. Likelihood and impact are Low,
Medium, High, or Critical. Owner is the Lific issue that must supply proof.

## R1: Undocumented HTTP write behavior

Likelihood: Medium. Impact: High.

Statement and invariant: Nix may change probe order, status handling, upload
routes, or retry behavior. Stock nix copy compatibility must not depend on
accidental sequencing.

Evidence: Nix 2.31.5 and 2.35.2 traces plus pinned upstream source are in
docs/evidence. Probe counts differ from the minimum semantic protocol.

Owner and mitigation: NARJ-2/NARJ-4. Treat probes as idempotent and unordered;
version the route contract; keep raw traces and source pins.

Detection and recovery: Run compatibility vectors on every supported Nix
update. Hold release or revert the declared client range.

Residual/disposition/proof: Medium, release-blocking until Linux, retry, and
proxy captures pass NARJ-17/NARJ-18.

## R2: Reimplementing existing products

Likelihood: High. Impact: High.

Statement and invariant: A greenfield cache may duplicate bincache or Kasha
without a material benefit. Narjar must remain the smallest useful profile.

Evidence: docs/prior-art.md.

Owner and mitigation: NARJ-3/NARJ-19/NARJ-20. Require matched startup, RSS,
CPU, stored-size, and operational comparisons. Adopt upstream if the
differential is not material.

Detection and recovery: Dependency/LOC growth or new DB/signing/recompression
scope reopens the decision. Stop implementation and upstream the delta.

Residual/disposition/proof: High, architecture gate blocker. NARJ-20 must choose
adopt, extract, or greenfield based on NARJ-19 evidence.

## R3: Native-store and flat-cache confusion

Likelihood: Medium. Impact: High.

Statement and invariant: Code may assume /nix/store registration or attempt to
serve native paths. The daemon must require no server Nix installation.

Evidence: Harmonia solves native-store serving; Nix file:// proves flat cache.

Owner and mitigation: NARJ-5. Exact validated route-to-file mapping and flat
layout; no libnix/native-store dependency.

Detection and recovery: Runtime closure check rejects Nix; E2E runs on a host
without server Nix. Revert any native-store coupling.

Residual/disposition/proof: Low after NARJ-18/NARJ-29.

## R4: Signature authority confusion

Likelihood: Medium. Impact: Critical.

Statement and invariant: Treating a write token as signing authority would let
a compromised uploader publish trusted malware. Only configured producer keys
may authorize narinfo.

Evidence: Server-signed bincache intentionally grants this authority; client-
signed Kasha demonstrates the alternative.

Owner and mitigation: NARJ-6/NARJ-12. Client-signed only; no server secret key;
verify a canonical Nix fingerprint against trusted public keys.

Detection and recovery: Negative untrusted-key E2E, signer identifier audit,
public-key overlap runbook. Revoke compromised public key and quarantine its
published narinfos.

Residual/disposition/proof: High until canonical fingerprint/signature vectors
and wrong-key tests pass NARJ-16/NARJ-18.

## R5: Narinfo/NAR mismatch or forged metadata

Likelihood: High for malicious writers. Impact: Critical.

Statement and invariant: Published narinfo must name the exact durable NAR and
store hash; no partial or mismatched pair is reader-visible.

Evidence: Wire capture shows NAR first and narinfo as final visibility marker.

Owner and mitigation: NARJ-8/NARJ-9. Stream SHA-256 and byte count; require
compression=none equality; strict route, Path, URL, hash, size, reference, and
signature validation; publish narinfo last.

Detection and recovery: Property/negative tests and offline reconcile detect
missing/mismatched pairs. Quarantine narinfo first, then investigate orphan NAR.

Residual/disposition/proof: Medium after fault injection and real-Nix refusal
tests NARJ-16/NARJ-18.

## R6: Compression and size amplification

Likelihood: Medium. Impact: High.

Statement and invariant: Compressed uploads can cause CPU/memory/disk
amplification. Resource use must stay bounded by configured raw bytes and
concurrency.

Evidence: Nix supports many codecs; prior art adds decompression/recompression
pipelines.

Owner and mitigation: NARJ-29. Reject HTTP Content-Encoding and unsupported
compressed suffixes; accept only fixed-length `.nar` and `.nar.xz` bodies; cap
both received and decompressed bytes; stream XZ validation with no NAR semantic
parser or recompressor.

Detection and recovery: Per-route byte counters, 413 tests, disk watermark.
Abort temporary and return admission failure.

Residual/disposition/proof: Low after oversize/slow-body tests NARJ-16/NARJ-17.

## R7: Truncation, corruption, and local disk faults

Likelihood: Medium. Impact: High.

Statement and invariant: Truncated uploads or bit rot must not yield trusted
published paths.

Evidence: HTTP bodies can end early; filesystem corruption is outside process
atomicity.

Owner and mitigation: NARJ-8/NARJ-13. Count and hash every upload; sync before
rename; narinfo last; offline full reconcile hashes objects.

Detection and recovery: Short-read/hash tests, scheduled reconcile, consumer
NarHash failures. Quarantine affected narinfos and restore immutable files from
backup/reupload.

Residual/disposition/proof: Medium; v0.1 detects upload corruption immediately
and latent corruption only during read/client verification or reconcile.

## R8: Rename and fsync crash windows

Likelihood: Medium. Impact: Critical.

Statement and invariant: A 201 must not precede durable data, and a crash must
never expose narinfo before its NAR.

Evidence: Rename atomicity does not imply power-loss durability; directory sync
is required.

Owner and mitigation: NARJ-9/NARJ-11. Same-filesystem temporaries, file sync,
no-replace publication, parent-directory sync, NAR before narinfo.

Detection and recovery: Fault injection at every write/sync/rename step;
restart state matrix; reconcile stale temporaries/orphans.

Residual/disposition/proof: High release blocker until NARJ-16 fault tests pass
on Linux filesystem targets.

## R9: Traversal and route ambiguity

Likelihood: High for exposed service. Impact: Critical.

Statement and invariant: No request may escape DATA or alias another immutable
object.

Evidence: HTTP percent-decoding and platform separators create multiple path
representations.

Owner and mitigation: NARJ-4/NARJ-10. Match strict ASCII route grammar before
path construction; decode once; reject slash encodings, dot segments, NUL,
Unicode, duplicate separators, unsupported suffixes.

Detection and recovery: Table/property/fuzz corpus across raw and encoded
paths. A finding is a release stop and security patch.

Residual/disposition/proof: Low after NARJ-16 fuzz/property gates.

## R10: Slow clients and resource exhaustion

Likelihood: High on untrusted networks. Impact: High.

Statement and invariant: Slow readers/uploaders, floods, descriptors, or
temporary files must not violate bounded memory or starve the server.

Evidence: One task/file/descriptor exists per admitted request.

Owner and mitigation: NARJ-8/NARJ-14. Global concurrency semaphore, header/body
limits, idle/progress deadlines, bounded buffers, create-new temporaries, proxy
connection limits, disk admission watermark.

Detection and recovery: Metrics/log counters without secrets; load tests at and
above admission cap. Return 429/413/507 and clean temporaries.

Residual/disposition/proof: Medium; single-process service can still be denied
within configured capacity. Document deployment rate limiting.

## R11: TLS and reverse-proxy mismatch

Likelihood: Medium. Impact: Critical for private credentials.

Statement and invariant: Basic tokens must never traverse an untrusted cleartext
network or appear in proxy logs; proxy buffering must not defeat streaming.

Evidence: Loopback traces deliberately omit TLS; configuration is unproven.

Owner and mitigation: NARJ-2/NARJ-14/NARJ-17. Bind privately, terminate TLS,
disable request buffering, preserve Content-Length/Authorization, align limits
and timeouts, redact logs.

Detection and recovery: Real proxy capture and config test. Revoke exposed
tokens, rotate credentials, fix proxy before restart.

Residual/disposition/proof: High release blocker until TLS/proxy E2E passes.

## R12: Token and producer-key rotation errors

Likelihood: Medium. Impact: High.

Statement and invariant: Rotation must not expose tokens, lock out all writers,
or invalidate still-cached narinfos unexpectedly.

Evidence: Nix positive metadata caching outlives a deployment; client public
keys are independently configured.

Owner and mitigation: NARJ-12/NARJ-14. Token add-then-revoke overlap; public-key
old/new overlap; no server signing key; mode-0600 files; atomic config reload.

Detection and recovery: Rotation integration test with old/new clients and
wrong-key negative case. Restore previous public key/token hash file.

Residual/disposition/proof: Medium after runbook tests; compromised producer
content still requires explicit quarantine.

## R13: Startup/RSS target and filesystem scale

Likelihood: Medium. Impact: High to product premise.

Statement and invariant: Startup under 100 ms and idle RSS under 30 MiB must not
grow with NAR size or require an unbounded scan.

Evidence: Filesystem route mapping removes the need for a startup index.

Owner and mitigation: NARJ-7/NARJ-19. No boot scan; lazy exact lookup; offline
reconcile; measure empty and modest caches against bincache.

Detection and recovery: Benchmark gates on startup median/p95 and settled RSS.
Adopt bincache or revise the premise if the differential is immaterial.

Residual/disposition/proof: High continuation blocker. The architecture gate
may authorize only the thin vertical slice required for matched measurement.

## R14: Unsafe or unnecessary dependencies

Likelihood: Medium. Impact: High.

Statement and invariant: Dependencies must not dominate closure, memory, audit
surface, or static-link feasibility.

Evidence: The initial crate has no runtime dependencies; planned HTTP, hash,
signature, and CLI work can expand quickly.

Owner and mitigation: NARJ-15/NARJ-29. Standard library first; one HTTP stack;
one SHA-256 implementation; one Ed25519 verifier; no DB, codec, TLS, NAR parser,
async trait framework, or general configuration framework without proof.

Detection and recovery: cargo tree, duplicate/features/license/advisory checks,
static ELF and runtime closure gates. Remove or replace violating dependency.

Residual/disposition/proof: Medium throughout implementation; every dependency
change reopens review.

## R15: GC, deletion, backup, and restore

Likelihood: Medium. Impact: High.

Statement and invariant: Deletion must not race reads or strand metadata; backup
must preserve a coherent published set.

Evidence: Content sharing and mutable indexes make GC difficult in prior art.

Owner and mitigation: NARJ-13/NARJ-14. No online delete or GC in v0.1; immutable
files; backup narinfo and NAR tree; restore then reconcile; stale temporaries
are outside the published set.

Detection and recovery: Restore drill and reconcile report. Missing NAR causes
narinfo quarantine; orphan NAR is retained.

Residual/disposition/proof: Low for v0.1 safety, High for disk growth and
operator capacity planning; disk watermark is mandatory.

## R16: Real-Nix and Linux proof gaps

Likelihood: High until tests exist. Impact: Critical.

Statement and invariant: Handler tests or flake evaluation cannot prove stock
Nix protocol behavior, trust enforcement, static Linux packaging, or proxy
deployment.

Evidence: Current Darwin trace succeeds; explicit static Linux build is blocked
because Tina is unreachable.

Owner and mitigation: NARJ-17/NARJ-18/NARJ-29. Real sockets, independent Nix
store, trusted/untrusted keys, Linux static binary, reverse proxy, and exact
trace assertions.

Detection and recovery: These are release gates, not warnings. Keep
implementation tickets incomplete until proof is attached.

Residual/disposition/proof: Critical blocker. No v0.1 approval without all
three tickets passing.

## Decision log

### D1: Flat cache, not native store

Accepted. Removes server Nix and maps validated routes directly to immutable
files. Rejected alternative: Harmonia/native /nix/store.

### D2: Client signing, not server signing

Accepted provisionally. Keeps write authority separate from trust authority.
Rejected alternative: bincache-style server signing.

### D3: Filesystem only, no database

Accepted provisionally. Exact route lookup requires no index; reconciliation is
offline. Rejected alternatives: redb and SQLite.

### D4: Store compression=none byte-for-byte

Accepted provisionally. No decompressor or recompressor; bounded stream hash and
copy. Rejected alternative: canonical zstd due CPU/dependency complexity.

### D5: Do not parse NAR semantics

Accepted. Narjar verifies signed hash/size metadata; consumer Nix is the semantic
parser. A duplicate parser adds attack surface without authenticity.

### D6: TLS at reverse proxy

Accepted provisionally. Keeps TLS stack out of the static binary. Deployment
proof remains a release gate.

### D7: No online GC or deletion

Accepted for v0.1. Avoids reader/deletion races and mutable reachability state.
Capacity planning and offline reconciliation remain required.

### D8: Greenfield implementation is conditional

Conditionally choose Narjar's greenfield thin vertical slice because its
approved profile removes the database, recompression, server signing key,
background workers, and startup index. NARJ-19 matched comparison decides
whether implementation may continue past that slice or must adopt bincache.
