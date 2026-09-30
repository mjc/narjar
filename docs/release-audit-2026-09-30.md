# Release audit — 2026-09-30

Reviewed `84f130b` on `main`. Documentation changes from this audit do not
change the reviewed Rust, Nix, or shell behavior. No release was published.

The Cargo package builds, tests, and installs. Release remains blocked by
recovery, HTTP framing, maintenance, and chunked-retention defects below.
Passing tests do not cover those failure paths.

## Scope and execution evidence

The review used SEM entity context and call graphs, one Rust reviewer, one
Nix/CI explorer, and two documentation workers. It covered production storage,
HTTP, authentication, server lifecycle, push, inventory, metrics, maintenance,
setup, the public NAR/identity API, dependency boundaries, Cargo packaging,
Nix/devenv configuration, module evaluation, CI, and selected research scripts.
All 58 tracked Markdown documents were read, including historical reports.
Legal texts and raw fixtures/logs were not rewritten.

Completed checks:

| Check | Result |
| --- | --- |
| `cargo nextest run --locked --workspace` | 442 passed; one skipped |
| Workspace, all-target/all-feature Clippy with `-D warnings` | Passed |
| Workspace, all-feature rustdoc with warnings denied | Passed |
| `cargo test --locked --doc` | Three doctests passed |
| `cargo fmt --all -- --check` | Passed |
| `bash ci/check-cargo-package.sh` | Passed |
| Packaged-source nextest | 419 passed; one skipped |
| Offline release install from extracted archive | Help/version checks passed |
| Cargo archive | 74 files; 285,914 bytes compressed |
| Current dependency advisory gate and historical vulnerability fixture | Passed |
| Separate fuzz package, locked compilation of all targets | Passed |
| Offline Linux/Darwin derivation and NixOS module evaluation | Passed |
| Targeted Nix source-filter and benchmark-launcher evaluation | Findings below |
| Documentation links, whitespace, and preserved command blocks | Checked |

The pinned nightly fuzz compiler warns about two uses of `fetch_update` being
renamed to `try_update`. Stable-toolchain Clippy is clean. Do not change the
stable API calls without checking the supported Rust version.

No VMs, deployments, live cache mutations, OCI tests, Darwin builds, full local
flake build, static-ELF execution, throughput benchmarks, or memory profiles
were run. Source-traced findings below are distinguished from runtime probes.
This is a release/maintenance audit, not evidence of absence of vulnerabilities.

## Correctness findings

### R1 — P1: journal creation and abandoned rewrites can prevent recovery

Evidence: `RecoveryState::begin`, `PublicationTransaction::transition`, and
`RecoveryState::transaction_names` in [recovery.rs](../src/storage/recovery.rs).

Initial records are created at their authoritative names before being written
and synchronized. Transitions stage a `.next-*` record, but recovery enumerates
all directory entries as transactions. Termination during either write can
leave an empty or partial record that the parser rejects, blocking restart.
Returned transition errors attempt cleanup; abrupt termination does not run it.

Use one atomic record-publication operation for initial and subsequent records.
Give scratch records a distinct classification and remove abandoned scratch
files without accepting malformed authoritative records. Keep durability
ordering explicit. Test interruptions before/after record write, record sync,
rename, and directory sync. Source-traced; no process-kill test was run.

### R2 — P2: HTTP reuse discards read-ahead and ignores unread bodies

Evidence: `Request::respond`, `Request::respond_file`, and
`BufferedHead::into_request` in [request.rs](../src/http_server/request.rs), plus
`process_next_request` in [server.rs](../src/server.rs).

Responses return only the socket for reuse. Bytes already read beyond the
first header are discarded with the request. Reuse also depends on the
Connection header rather than complete, supported request-body framing.

Two loopback probes against the built request implementation reproduced:

- Two GETs sent in one write: the first succeeds; parsing the second times out
  with `WouldBlock` because its buffered bytes were discarded.
- A GET with declared body length, whose body arrives after its response:
  body bytes spelling a request are accepted as the next request (`/body`).

The probes did not establish an authentication bypass or proxy exploit.
Close connections when framing is unsupported, bodies remain unread, or
read-ahead would otherwise be lost. If pipelining is supported, retain a
connection-owned input buffer across requests. Test coalesced requests, delayed
bodies, rejected transfer encoding, and both ordinary/file responses.

### R3 — P1: destructive maintenance can invalidate pending recovery records

Evidence: `run_with_lock_acquired` in [gc.rs](../src/storage/gc.rs), delete in
[operator/mod.rs](../src/operator/mod.rs), and `recover_transaction` in
[recovery.rs](../src/storage/recovery.rs).

Maintenance acquires storage but does not complete pending recovery before
deletion. A crash can leave a `published` transaction; GC/delete can then remove
that transaction's destination. Subsequent recovery requires the destination
and refuses restart.

Create one exclusive maintenance entry path that validates availability and
completes recovery before exposing mutation operations. Hold the lease through
completion. A small recovered-storage capability can encode this ordering;
another independent boolean cannot. Test crash record → GC/delete → restart,
including a published record for an object selected for deletion. Source-traced.

### R4 — P2: chunk-batch accounting uses cumulative lengths

Evidence: `next_chunk_specifications` and `publish_next_batch` in
[chunk_store.rs](../src/storage/chunk_store.rs).

Every specification computes `nar_end - self.previous_end`, but
`self.previous_end` is unchanged during batch construction. Two 1 MiB chunks
therefore carry accounting lengths 1 MiB and 2 MiB. Reservations and chunk byte
metrics use those values even though the second chunk contains only 1 MiB.
Larger batches amplify false capacity rejection.

Derive each length from its checked `end - start` range. Keep absolute NAR
offsets separate from chunk byte counts, preferably in the specification's
constructor. Test several chunks in one batch, exact available capacity,
materialization-credit release, and unique/reused byte counters. Source-traced;
payload reconstruction itself was not shown to be wrong.

### R5 — P1: chunked GC does not implement the flat retention policy

Evidence: `run_chunked`, `select_chunked`, and `apply_chunked` in
[gc.rs](../src/storage/gc.rs), plus `delete_unmarked_manifests` in
[chunk_store.rs](../src/storage/chunk_store.rs).

Chunked selection receives the target but not the maximum-pressure threshold,
so it can evict between target and maximum where flat GC would not. Metadata
age protects published entries, but orphan derivative deletion and manifest
sweeping do not apply the configured minimum age. A recently uploaded object
awaiting its separate narinfo PUT can be reclaimed despite that grace period.

Share policy eligibility and pressure decisions across backends; keep backend
byte accounting and physical deletion separate. Mark retained orphan manifests
as live before chunk sweeping. Test identical policy scenarios for both
backends: between target/max, recently uploaded orphans, old orphans, protected
roots, and mixed recent/old manifests sharing chunks. Source-traced.

### R6 — P2: maintenance history is modified before lease acquisition

Evidence: maintenance entry points in [operator/mod.rs](../src/operator/mod.rs)
and record lifecycle in [maintenance.rs](../src/maintenance.rs).

A second command can overwrite `.started`, fail to acquire storage, then
remove the first command's active history. Acquire storage before starting the
recorder and retain it until the recorder finishes. Reuse the ordering already
used by GC. Test a blocked competing command against an active recorded
operation. Source-traced.

### R7 — P3: abandoned upload records have no in-process bound

Evidence: `UploadTemporary::drop` and staged upload ownership in
[ingest.rs](../src/storage/ingest.rs).

Wrong-hash and disconnected uploads remove their temporary payload but retain
the recovery transaction. Repeated failures accumulate records and inodes until
recovery runs. Retaining uncertain outcomes is intentional and covered by fault
tests; this is a lifecycle/resource concern, not an established release blocker.
Reuse the cleanup-before-cancel ownership pattern only for conclusively
abandoned pre-publication transactions, preserving records when cleanup or
publication outcomes are uncertain. Test repeated rejected uploads and failure
of cleanup itself. Source-traced.

### R8 — P2: setup rejects bare relative directory names

Evidence: `absolute_destination` in [setup.rs](../src/setup.rs).

`Path::parent()` for `cache` yields an empty path, not `None`; the existing
fallback therefore still canonicalizes an empty path. Treat an empty parent
as `.`. Cover bare names, `./name`, absolute destinations, nonexistent parents,
and rejected root/dot destinations. Source-traced.

### R9 — P2: the public decoder treats transient interruption as failure

Evidence: `read_hashed_limited_bytes` and the final EOF probe in
[nar.rs](../src/nar.rs).

A valid NAR decodes normally, but a reader returning `Interrupted` once before
the same bytes produces `Err(Io(Kind(Interrupted)))`. This was reproduced with
the public decoder and encoder. Centralize interruption retry for hashed reads
and the trailing-byte probe; preserve byte limits, hash updates, and other
source errors. Test interruptions during tokens, file chunks, and final EOF.

## Nix, CI, and tooling findings

### N1 — P1: GC and serving use different filesystem identities

Evidence: `systemd.services.narjar-gc` in [module.nix](../nix/module.nix) and
`create_marker` in [recovery.rs](../src/storage/recovery.rs).

The GC service has no User/DynamicUser identity and runs as root. Interrupted
GC can leave root-owned 0600 recovery files that the dynamic serving UID cannot
read. Share server identity/state-directory configuration with maintenance;
keep the systemctl stop/start operations privileged explicitly. Add module
evaluation assertions for identities and unprivileged, same-UID recovery tests.
This failure path was source-traced, not executed through systemd in this audit.

### N2 — P1, conditional: OCI cleanup can reset unrelated Podman storage

Evidence: `cleanup` in [oci-e2e.sh](../tests/oci-e2e.sh).

The script replaces HOME but retains inherited `XDG_DATA_HOME`; it runs
`podman system reset --force` on exit. Under an inherited storage configuration,
that reset can act on the user's existing container store. Explicitly isolate
Podman storage and run roots for every invocation and remove global reset.
Test cleanup argv against inherited XDG/container settings without operating
on a real container store. The destructive script was not run during this audit.

### N3 — P2: the ZFS sampler builds invalid property arguments

Evidence: `zfsSampleCollector` in [module.nix](../nix/module.nix).

`zfs get` receives each property as a separate argument instead of one
comma-separated property list. Later properties are interpreted as datasets,
so the collector fails instead of updating its sample. Join the property list
before shell escaping; test generated argv with a fake ZFS executable. No live
ZFS collector was invoked.

### N4 — P2: the packaged continuation benchmark cannot resolve its inputs

Evidence: launcher in [flake.nix](../flake.nix), input lookup in
[continuation-benchmark](../scripts/continuation-benchmark), and the relative
patch in [bincache.nix](../benchmarks/bincache.nix).

The wrapper sets `NARJAR_BINCACHE_EXPR`, while the script uses `BINCACHE_EXPR`.
It inlines a script whose repository-root lookup depends on its original file
location. A separately copied Nix expression also loses its sibling patch.
Execute the script from filtered repository source and resolve the expression
and patch from that same source. Include curl/util-linux in runtime inputs.
Targeted Nix evaluation confirmed the copied expression's patch is absent.
Test the packaged launcher's input resolution, not only the source script.

### N5 — P2: historical Rust probes enter normal application build inputs

Evidence: `mkCraneBuild` in [flake.nix](../flake.nix).

The Cargo source filter starts from the unfiltered repository rather than the
results-excluding `repositorySrc`. Nix evaluation confirmed that a Rust probe
under `benchmarks/results/` enters application source. Changes to old evidence
therefore invalidate builds despite not being part of the program. Compose
the Cargo filter over `repositorySrc`; assert that retained Cargo/test fixtures
exist and benchmark results do not.

### N6 — P2: invalid GC thresholds pass module evaluation

Evidence: module assertions and GC service in [module.nix](../nix/module.nix).

`maxBytes = 1000; targetBytes = 2000` evaluates successfully, but the CLI rejects
it after the service has stopped Narjar. Validate this cross-option constraint
in the module, using the same relation as CLI admission. Add an invalid-module
evaluation case; no VM is needed.

### N7 — P2: saved check commands enforce different gates

Evidence: tasks in [devenv.nix](../devenv.nix) and checks in
[flake.nix](../flake.nix).

Developer Clippy permits warnings while CI denies them. The flake's test check
uses Cargo test without workspace selection; packaged-source checks separately
use nextest. The docs check does not deny rustdoc warnings. Align check flags,
use nextest for ordinary tests, explicitly decide workspace coverage, and keep
packaged-root tests distinct from workspace tests. Add a command-contract check
rather than another independent list of approximately equivalent commands.

### N8 — P2: advertised Darwin support has no CI execution lane

Evidence: supported outputs in [flake.nix](../flake.nix) and Linux-only
[flake.yml](../.github/workflows/flake.yml).

Darwin derivations evaluate but that does not establish compilation/runtime
support. Add an Apple-silicon package/test lane for flat storage and the
documented API, or narrow the release support claim. Keep NixOS module checks
evaluation-only; this does not require restoring VM tests.

## Refactor priorities

These are maintenance findings, not additional proven correctness failures.

1. Centralize recovered, exclusively leased maintenance entry and completion.
   This addresses R3/R6/N1 rather than adding guards to each command.
2. Share GC retention/protection policy between flat and chunked storage.
   Keep backend reachability/byte accounting concrete. This addresses R5 and
   removes duplicate root-closure traversal and report construction.
3. Use one owned journal/staging lifecycle and atomic record writer. Encode
   pre-link versus durable publication states so cleanup cannot cancel evidence
   needed after publication or an uncertain fault outcome. This addresses R1/R7.
4. Give HTTP connection state ownership of unread bytes and framing. Request
   handlers should not each guess whether a socket is reusable. This addresses R2.
5. Bound `DeliveryValidationCache` in [state.rs](../src/storage/state.rs).
   Its HashMap retains a proof for every distinct object read. Eviction can
   trigger revalidation; it must not turn missing evidence into acceptance.
6. Reuse filesystem-capacity calculations in doctor instead of separately
   encoding them. Document each FFI call's actual safety conditions in
   [operator/mod.rs](../src/operator/mod.rs). No undefined behavior was shown.
7. Split `Decoder::decode_node` into named directory/file/symlink operations.
   Keep canonicality checks at parse boundaries and use exhaustive dispatch.
   In the encoder, replace overlapping root/finished/child-open flags with
   data-bearing states where this removes guards; do not parameterize the
   application with an event-state type matrix.
8. Parse/format fixed SHA-256 identities with fixed 52/32-byte scratch arrays
   in [object.rs](../src/object.rs). Parsing currently allocates reversed input
   and decoded vectors; formatting allocates a String even through Display.
   Preserve canonical Nix32 validation and public hash-purpose distinctions.
9. Review the application/library dependency boundary. Public NAR-only consumers
   still compile the private application and its SQLite/TLS/CLI dependencies.
   This is documented, not a package-install failure. Avoid introducing a
   large feature matrix solely to hide that cost.
10. Keep research scripts standalone. `scripts/nar-corpus` is independent,
    but [nar-chunking/Cargo.toml](../scripts/nar-chunking/Cargo.toml) depends on
    the root crate and its main imports the root decoder. Remove that coupling
    or delete the obsolete experiment if it is no longer needed; do not move
    research tools back into the production binary.

No unused-dependency claim follows solely from duplicate dependency versions.
The two SHA-2 major versions are currently required by separate dependencies;
their removal needs an upstream-compatible change, not a manifest deletion.

## Documentation corrections

Prose cleanup preserves technical uncertainty, measurements, commands, and
explicit publishing approval. Current documentation also needs to agree with
implemented behavior rather than retain obsolete design assertions:

- Native push reads the local store directly; HTTP credentials can be sent
  over plaintext only with the explicit insecure override.
- Compressed URL names identify FileHash, not NarHash.
- Early semantic proposals and dependency budgets are distinguished from the
  implemented API/defaults and current dependency set.
- The codec threat model describes decoder recursion rather than claiming an
  iterative decoder, and distinguishes codec use from server ingestion.
- Compression/storage guidance and the old byte-preserved-ingress decision are
  reconciled with canonical raw storage and independently selected egress.
- The superseded baseline report carries its existing evidence warning, not
  only the adjacent decision document.

Historical measurements were not rerun or rewritten as current measurements.
README links are absolute repository links and are not broken by excluding
the docs directory from the Cargo archive.

## Release order

Fix recovery and maintenance ordering/identity first, then HTTP framing,
chunked accounting/retention, and isolated OCI cleanup. Fix module/tooling
contracts before relying on them as release gates. Follow with bounded-memory
and code-structure refactors backed by the regression cases above.

Re-run the affected tests and locked release gates on the resulting candidate.
Registry ownership, version/tag selection, release notes, and publishing still
require the manual procedure and explicit consent in [release.md](release.md).
