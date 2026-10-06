# Narjar v0.1 operations and resilience contract

Status: accepted v0.1 operations contract; remaining deployment evidence is
tracked in the risk register and open Lific work.

## CLI

The binary name is narjar. Secrets are never accepted as positional values or
normal flag values.

~~~text
narjar init
  --data-dir PATH
  [--priority 30]
  [--private-read]
  [--storage-backend flat|chunked]

narjar serve
  --data-dir PATH
  [--listen 127.0.0.1:5000]
  [--workers 8]
  [--max-in-flight 64]
  [--max-nar-bytes 17179869184]
  [--max-encoded-nar-bytes 17179869184]
  [--max-decoder-memory-bytes 134217728]
  [--min-free-bytes 1073741824]
  [--shutdown-grace-seconds 30]
  [--io-timeout-seconds 30]
  [--storage-backend flat|chunked]

narjar token create
  --data-dir PATH
  --scope read|write
  [--name LABEL]

narjar token revoke
  --data-dir PATH
  --scope read|write
  --name LABEL

narjar reconcile
  --data-dir PATH
  [--verify-hashes]
  [--json]
  [--structural]
  [--limit N]
  [--min-age-seconds N]
  [--storage-backend flat|chunked]

narjar cleanup
  --data-dir PATH
  [--min-age-seconds N]
  [--limit N]
  [--json]
  [--storage-backend flat|chunked]

narjar verify
  --data-dir PATH
  [--json]
  [--storage-backend flat|chunked]

narjar delete
  --data-dir PATH
  --store-hash HASH
  [--json]
  [--storage-backend flat|chunked]

narjar gc
  --data-dir PATH
  [--max-bytes BYTES]
  [--target-bytes BYTES]
  [--max-age-seconds SECONDS]
  [--min-age-seconds SECONDS]
  [--protected-roots PATH]
  [--dry-run | --apply]
  [--json]
  [--storage-backend flat|chunked]

narjar list-orphans
  --data-dir PATH
  [--verify-hashes]
  [--json]
  [--storage-backend flat|chunked]

narjar doctor
  --data-dir PATH
  [--json]

narjar key generate
  --name LABEL
  --secret-key-file PATH
  --public-key-file PATH

narjar stats
  --url HTTP_URL
  [--netrc-file PATH]

narjar push
  --to STORE_URI
  [--jobs N]
  [--compression none|zstd|xz]
  [--timeout-seconds N]
  [--netrc-file PATH]
  [--signing-key-file PATH]
  [--refresh]
  [--ignore-conflicts]
  INSTALLABLE...
~~~

init creates the deterministic layout, nix-cache-info, empty token files, and
trusted-public-keys with restrictive modes. `--storage-backend` writes the
immutable layout descriptor and creates the chunk directories when `chunked`
is selected; it defaults to `flat`. A chunked descriptor records the supported
`mincdc-hash4-v2` profile (256 KiB minimum, 1 MiB maximum). It refuses a
non-empty incompatible directory; it does not infer or convert an older
layout. Chunked storage is supported only on Linux. Flat storage is supported
on Apple Silicon macOS and covered by a native CI package/test lane.
`init`, `serve`, and maintenance commands reject a chunked
selection before opening storage because macOS has no verified durability
sequence for syncing chunk data and shard entries before manifest publication.

token create generates a random 256-bit token, writes only its SHA-256 hash and
label atomically to the scope file, and prints the secret once to stdout.
Callers redirect stdout to a mode-0600 secret store. token revoke removes one
label by atomic file replacement. The secret itself is never in argv, an
environment variable, logs, or the hash file.

`push` takes concrete `/nix/store/...` paths, reads the local Nix store's SQLite
metadata database, and orders their closures into deterministic dependency
waves. It serializes NARs directly and uploads each NAR followed by its signed
narinfo. Independent paths within a wave use up to `--jobs` workers. With
`--signing-key-file`, it signs the closure's metadata in memory before uploading;
it does not modify the local store database or invoke Nix subprocesses.
`--compression` selects the uploaded NAR representation (`none`, `zstd`, or
`xz`) and defaults to `none`; the server independently selects its stored and
served representations. Uploads use fixed-length streamed requests and the
server's atomic per-object publication. The client needs read access to the
store and its metadata database. It protects the requested roots before reading
closure metadata. Direct writable-state access records NUL-separated paths in
`$NIX_STATE_DIR/temproots/<pid>` (default `/nix/var/nix/temproots/<pid>`) and
holds an exclusive file lock for the push. Guards in the same process share
that file. Nix's `gc.lock` is held shared only while validating paths,
registering roots, and reading metadata, not during uploads. When the last
guard closes the file, Nix GC can reclaim it without retaining its paths.
This also holds after SIGKILL; no destructor or signal handler is required.
Normal unprivileged users register temporary roots with `AddTempRoot` through
the native Nix daemon
socket and keep that connection alive for the entire push. A missing lock file
is created only when the local state directory is writable; symlinks and
non-regular lock files are rejected. Permission-denied or read-only failures
opening the lock or installing local roots use the same daemon path. Invalid
paths and other rooting failures remain errors. No separate root-directory
configuration, Nix subprocess, or additional dependency is needed. Failure to
establish roots aborts the push before metadata lookup.
Each native HTTP request has a 30-second timeout by default; `--timeout-seconds` or
`NARJAR_PUSH_TIMEOUT_SECONDS` changes it.

`--netrc-file` supplies HTTP Basic credentials. They are sent only over HTTPS
unless `--insecure-http` explicitly permits sending them over plain HTTP. Use
HTTPS for remote access. A request started over HTTP without that override
remains unauthenticated after an HTTP-to-HTTPS redirect; use an HTTPS target
from the start. The netrc file must have restrictive permissions.

Shared publishers can pass `--ignore-conflicts` to skip a store path whose
immutable destination already has a different NAR identity and continue the
closure. The existing destination remains untouched; without this explicit
option, the push fails so the conflict is visible.

The native client transfers store-path NARs and narinfos only. Realisations,
build logs, `.ls` listings, and other store-daemon metadata are outside this
client’s upload contract; use the corresponding stock Nix operation when those
surfaces are required.

delete is offline-only: it refuses while the serve lock is held, removes the
published narinfo after validation and directory sync, and leaves
the canonical object. list-orphans reports unreferenced flat NARs or chunked
manifests. For chunked storage, `verify` and `reconcile --verify-hashes`
reconstruct the canonical stream and inspect the referenced chunks.
gc is also offline-only and takes the same data-directory lock. It defaults to
dry-run unless --apply is explicit, validates the complete published inventory
before selecting anything, and evicts FIFO by narinfo filesystem modification
time. The minimum age applies to published narinfos and orphan NARs. A
protected-roots file accepts canonical /nix/store paths or store hashes, one per
line; references reachable from present roots are retained transitively.

The report labels `before_bytes`, `after_bytes`, and `evicted_bytes` as
`accounting_basis=logical`: they are sums of logical file lengths, not physical
space reclaimed. It includes the target status, plus counts and byte totals for
protected and age-eligible entries, selected evictions, shared NAR objects,
orphan NARs, temporary entries, and malformed inputs. It also reports missing
roots and missing transitive references. Category byte totals may overlap when a
shared NAR belongs to more than one category. Malformed
published metadata still aborts the pass before deletion, so its report count
and byte total are zero on a successful scan; the error identifies the
offending path. Compression, sparse/reflinked extents, and snapshot-held space
are filesystem observations outside these deterministic logical totals.

Apply removes narinfo first and syncs the cache directory. Flat referenced NARs
are removed only after their final narinfo is gone. Chunked apply marks the
manifests retained by remaining narinfos, follows each manifest's chunk
records, then removes unreferenced manifests and shared chunks. Malformed
metadata, missing canonical objects, symlinked narinfos, or an unreadable
manifest abort the pass before destructive sweep. No online delete endpoint or
resident GC worker is part of this interface.

## Configuration and precedence

Non-secret configuration precedence is:

1. Command-line flag.
2. NARJAR_* environment variable.
3. Compiled default.

Secret-bearing configuration is only in DATA/auth/*.tokens, DATA/trusted-public-keys,
or an explicit mode-0600 file path. There is no inline token/key environment
variable.

Supported environment names mirror flags:

~~~text
NARJAR_DATA_DIR
NARJAR_LISTEN
NARJAR_WORKERS
NARJAR_MAX_IN_FLIGHT
NARJAR_MAX_NAR_BYTES
NARJAR_MAX_ENCODED_NAR_BYTES
NARJAR_MAX_DECODER_MEMORY_BYTES
NARJAR_MIN_FREE_BYTES
NARJAR_SHUTDOWN_GRACE_SECONDS
NARJAR_IO_TIMEOUT_SECONDS
NARJAR_PUSH_TIMEOUT_SECONDS
~~~

The compiled defaults bind to loopback, use 8 workers, admit at most 64
in-flight requests, cap decoded and encoded NARs independently at 16 GiB,
limit compressed decoder working memory to 128 MiB per upload, and preserve a
1 GiB free-space reserve. `--data-dir` has no default. A flag or environment
value may override each numeric policy; the shutdown grace defaults to 30 seconds and must be
positive, while zero is valid only for the free-space reserve. Listen addresses
must be numeric IP socket addresses so startup never depends on DNS.

Compressed uploads that exceed the decoder-memory limit are rejected with
HTTP 422 before the decoder allocates beyond the limit; staged output is
removed and never published. Encoded-size excess is HTTP 413; decoded-size
excess is HTTP 422. Decoding runs in the bounded publication
worker pool, so at most `workers` decoders can be active and their configured
aggregate memory ceiling is `workers × maxDecoderMemoryBytes`.

A TOML configuration file is an explicit v0.1 non-goal. It would add a parser
and duplicate the systemd/container environment boundary. If future option
count makes that trade worthwhile, flags continue to override file values and
environment continues to override only non-secret values.

Example fresh start:

~~~sh
install -d -m 0700 /var/lib/narjar
narjar init --data-dir /var/lib/narjar
narjar token create --data-dir /var/lib/narjar --scope write --name ci > /run/credentials/narjar-ci-token
narjar key generate --name narjar-producer --secret-key-file /run/credentials/narjar-producer.sec --public-key-file /var/lib/narjar/narjar-producer.pub
install -m 0600 producer-public-keys /var/lib/narjar/trusted-public-keys
narjar serve --data-dir /var/lib/narjar --listen 127.0.0.1:5000
~~~

## File ownership and permissions

The service runs as a dedicated unprivileged user.

| Path | Mode | Notes |
| --- | ---: | --- |
| DATA | 0700 | service user owns it |
| DATA/nar, DATA/nar/.tmp, DATA/realisations, DATA/realisations/.tmp, and DATA/.tmp | 0700 | no direct web-server access |
| NAR/narinfo/cache-info | 0600 | served only through process |
| auth token files | 0600 | hashes, still security-sensitive |
| generated signing secret | 0600 | create outside DATA and provision as a runtime credential |
| generated signing public key | 0644 | distribute to producers and trust stores as required |
| trusted-public-keys | 0600 | trust boundary material |
| lock | 0600 | single serving process |

The reverse proxy does not read DATA.

## Request concurrency and timeouts

serve creates a fixed worker set and a bounded queue. max-in-flight limits
requests that have begun processing; excess requests receive 429 when possible
or remain outside Narjar in the proxy accept queue.

Memory includes the server baseline, bounded connections and queues, metadata,
and each active worker's scratch buffers, codec working memory, and backend
state. The decoder budget defaults to 128 MiB per compressed upload; eight
active workers can therefore admit up to 1 GiB of decoder budgets alone. This
is not an RSS ceiling. Chunked ingestion also holds bounded chunk batches and
stages manifest descriptors on disk. Payloads are streamed rather than held in
object-sized buffers.

Header parsing limits come from Narjar's fixed parser plus route checks. Content-
Length is required before upload admission. Each accepted socket uses the
`--io-timeout-seconds` / `NARJAR_IO_TIMEOUT_SECONDS` limit (30 seconds by
default) as an idle-progress deadline for request headers, request bodies, and
response writes. The deadline applies to each blocking read or write, so a
large transfer may exceed 30 seconds when every interval makes progress. A
stalled client releases its worker and upload admission when the socket
operation times out. A reverse proxy may use stricter limits, but direct use
does not depend on proxy enforcement. NAR size and minimum free-space checks
happen before and during the stream.

Publication workers are bounded by `--workers` and process independent PUTs
concurrently. Each write reserves its declared body size against available
staging capacity before it enters the queue. Each upload then writes a private
temporary file and a durable record under `.narjar-transactions` before
streaming its body. The record durably advances through `staging`, `streaming`,
`validated`, `linked`, and `published` states at the corresponding filesystem
boundaries. Invalid binary records stop recovery without discarding evidence;
text records are not supported. Final link/compare, destination-directory sync,
and flat canonical-object acquisition share the destination lock. Binding waits
until a publisher can no longer roll back its link. Identical retries must
complete that same directory barrier; chunked binding synchronizes the manifest
directory. Unrelated destinations do not wait behind a slow body or decoder.
The queue remains bounded and exposes depth and wait metrics; excess requests
receive 429 when admission is full.

If a process stops during publication, the transaction record keeps the
temporary path and durable state recoverable without making an incomplete final
object visible. Startup checks published references, validates each recovery
record, removes recorded temporary state, and only then writes the clean marker.
During that recovery check, every trusted narinfo must have its
referenced payloads available at the declared sizes. Flat storage checks file
metadata; chunked storage verifies the manifest and each chunk's presence and
size. Startup stops at the first invalid pair and reports progress and elapsed
time without reading payload bytes. Run `narjar verify` for a full content scan.
Concurrent writers still use private temporary files and atomic
link-no-replace, so a retry is identical success or a deterministic conflict.

## Durable upload state machine

~~~text
ABSENT
  -> TEMP_OPEN
  -> STREAMING
  -> VALIDATED
  -> TEMP_SYNCED
  -> FINAL_LINKED
  -> DIRECTORY_SYNCED
  -> DURABLE

Any failure before FINAL_LINKED:
  -> TEMP_ABANDONED or TEMP_REMOVED
  -> ABSENT from reader perspective

Crash after FINAL_LINKED before DIRECTORY_SYNCED:
  -> UNKNOWN_DURABILITY
  -> reconcile classifies existing final; no 201 was returned

Existing final:
  -> compare identity
  -> IDENTICAL (idempotent success)
  -> CONFLICT (409, no mutation)
~~~

Narinfo uses the same state machine only after its referenced NAR is DURABLE and
all metadata/signature checks pass. Narinfo DIRECTORY_SYNCED is the store-path
publication point.

## Restart matrix

| Durable files after crash | Reader behavior | Reconcile result |
| --- | --- | --- |
| temp only | invisible | temporary, age classified |
| canonical object only | invisible as store path | orphan flat NAR or chunked manifest/chunks |
| canonical object plus narinfo temp | invisible as store path | orphan canonical object plus temporary |
| canonical object plus published narinfo | readable after backend-specific validation | valid pair or corruption finding |
| narinfo without canonical object | narinfo is quarantinable corruption; normal server returns 404/500 rather than bytes | missing canonical object |
| malformed final filename | unreachable by valid route | unknown/invalid file |

Startup validates the fixed layout and lock, verifies the published inventory
when recovery records are present, then removes only those recorded temporary
objects before serving. For a flat root that inventory points at a regular NAR
file; for a chunked root it points at a checksum-validated manifest and its
referenced regular chunk files. Reconciliation remains deterministic and
operator-triggered for other stale temporary files.

Server-generated compressed egress has a durable receipt under
`.narjar-egress/` binding one canonical raw identity and codec to the exact
encoded hash and size. Recovery removes malformed receipts and receipts whose
canonical raw source no longer exists. It retains a well-formed receipt when
the derivative is missing, truncated, or corrupt so a later request can
reproduce the recorded identity. Materialization verifies the replacement
identity before an atomic repair rename; ordinary uploaded NAR and narinfo
destinations remain immutable no-replace publications.

Compressed uploads durably record their encoded-to-raw identity in
`.narjar-ingress/`. Compressed narinfo publication requires a matching receipt;
missing, malformed, or mismatched receipts reject publication. Upload the
payload again to restore that evidence: the original compressed bytes are not
retained for a verification fallback. `.narjar-validation/` is reserved and is
not the ingress receipt store.

Narinfo binding checks canonical-object identity and durability. Flat binding
hashes a file on a verification-cache miss. Initial GET/HEAD availability lookup
uses type and size; flat delivery then verifies the opened file's identity on a
cache miss. Chunked binding and delivery check manifests and chunk availability.
Use `narjar verify` or `narjar reconcile --verify-hashes` for a full content scan,
including detection of same-size out-of-band mutation.

## Disk-full and I/O failure

Before accepting a NAR, Narjar checks the receiving `DATA/nar/.tmp`
filesystem for declared length plus reserve and at least one free inode. This
is admission guidance, not a guarantee: concurrent writers and other processes
can consume space or inodes.

ENOSPC and EDQUOT return 507 after closing and attempting to remove the temp;
inode exhaustion is also reported as 507 and read-only transitions as 503. EIO,
sync, or directory-sync failure returns 500 and never claims success. Recovery
records identify staged resources requiring cleanup; Narjar does not generate
request IDs. Metrics expose fixed-cardinality counters for no-space, quota,
inode, and read-only pressure.

A missing payload at route lookup or opening returns 404. Operational errors and
verification failures detected before response headers return 500. A failure
during body transfer aborts the connection; it cannot replace headers already
sent. Narjar does not maintain a reverse index of every published reference on
that lookup path; recovery and explicit verification detect metadata whose
payload has gone missing.

## Reconcile classifications

reconcile scans bounded directory entries and emits one record per finding:

- valid_pair
- orphan_nar
- missing_nar
- malformed_narinfo
- hash_or_size_mismatch
- untrusted_signature
- temp_young
- temp_stale
- invalid_filename
- unknown_file
- invalid_permissions

Default reconcile is read-only. --verify-hashes reads every referenced object
and is O(total NAR bytes). Without it, validation is O(narinfo bytes plus
metadata calls). JSON output is newline-delimited with stable class, validated
identifier, and action recommendation.

verify is reconcile --verify-hashes with a nonzero exit status for any invalid
published pair. list-orphans filters the read-only report.

No command turns an orphan into a published path.

## Backup and restore

The portable backup boundary is the complete data directory, copied while the
serving process is stopped and the DATA lease is released. A live `rsync` is
convergent synchronization, not a point-in-time backup: it may capture a NAR
and its narinfo at different moments.

For a live convergent copy when downtime is not available, exclude the contents
of every `.tmp` directory, preserving the directories themselves, and run
`verify` on the destination before using it. This is not a substitute for the
stopped-service procedure when a strict point-in-time boundary is required.

For a consistent portable copy:

1. Stop Narjar and wait for the process to exit.
2. Copy the complete data directory, including `.narjar-clean`,
   `.narjar-recovery`, `.narjar-transactions/`, `.narjar-layout`,
   `.narjar-chunks/` and `.narjar-manifests/` for a chunked root, `lock`,
   `nar/`, `.tmp/`, `realisations/`, `.narjar-validation/`,
   `.narjar-ingress/`, `.narjar-egress/`, `nix-cache-info`,
   `trusted-public-keys`, and `auth/`.
3. Preserve the directory and file permissions; do not expose the copy while
   it contains credentials.
4. On the destination, require `doctor` to exit successfully, then run
   `reconcile --verify-hashes` and `verify` before starting Narjar.
5. Start Narjar and require `GET /readyz` to return `200` before routing
   consumers to it.

`trusted-public-keys` and `auth/*.tokens` are part of the service boundary. Keep
them only when restoring the same trust and authorization boundary, and protect
the backup accordingly. If they are intentionally excluded, install fresh
trust material and rotate all tokens before starting the destination; a
restore without those files must not be treated as ready.

Filesystem snapshots are an external alternative, but the snapshot must include
the recovery marker, trust material, and credentials according to that same
policy. A corrupt or incomplete copy must remain offline: `doctor`,
`reconcile`, or `verify` must pass before readiness is considered meaningful.

Executable backup/restore coverage is the
[`restored_cache_verifies_before_serving`](../tests/cli.rs) integration test;
it initializes a fresh destination layout, restores the cache files, runs
reconciliation, verification, and doctor, then starts the restored service before
accepting readiness.

### Optional ZFS snapshot and replication workflow

ZFS operations stay outside Narjar. Substitute an explicitly verified dataset
name for `pool/narjar-data`; never infer a production target from a mountpoint
or copy these commands onto an unrelated pool.

First confirm the DATA dataset, mountpoint, and policy before taking a snapshot:

~~~sh
dataset=pool/narjar-data
pool=${dataset%%/*}
test "$(zfs get -H -o value mountpoint "$dataset")" = /var/lib/narjar
zfs get -H -o property,value \
  mountpoint,compression,atime,sync,dedup,quota,refquota,refreservation \
  "$dataset"
~~~

For a single DATA dataset, stopping Narjar and taking one snapshot gives a
point-in-time application boundary. If DATA is split across child datasets,
stop the service and use one recursive snapshot boundary; independent
snapshots are not an atomic multi-dataset backup.

~~~sh
snapshot="narjar-$(date +%Y%m%d-%H%M%S)"
set -euo pipefail
restarted=0
restart_narjar() {
  if [ "$restarted" -eq 0 ]; then
    systemctl start narjar.service
  fi
}
trap restart_narjar EXIT
systemctl stop narjar.service
zfs snapshot -r "$dataset@$snapshot"
zfs hold -r narjar:backup "$dataset@$snapshot"
narjar verify --data-dir /var/lib/narjar
systemctl start narjar.service
restarted=1
trap - EXIT
~~~

Record the dry-run stream size before sending. Send to a new, offline receive
target and run `doctor`, `reconcile --verify-hashes`, and `verify` there before
using it. An incremental stream requires that the destination retain the base
snapshot; use `-R` for a recursive dataset tree.

~~~sh
set -euo pipefail
target=backup/narjar-restore
zfs send -nP -R "$dataset@$snapshot"
zfs send -R "$dataset@$snapshot" | zfs receive -u "$target"

zfs mount "$target"
restore_data_dir="$(zfs get -H -o value mountpoint "$target")"
narjar doctor --data-dir "$restore_data_dir"
narjar reconcile --data-dir "$restore_data_dir" --verify-hashes
narjar verify --data-dir "$restore_data_dir"
zfs unmount "$target"

base=narjar-previous
next=narjar-next
zfs snapshot -r "$dataset@$next"
zfs send -nP -R -i "$dataset@$base" "$dataset@$next"
zfs send -R -i "$dataset@$base" "$dataset@$next" | zfs receive -u "$target"
~~~

If a send or receive fails, keep the receive target offline and treat it as an
incomplete restore; do not route Narjar to it. A successful ZFS receive proves
that the stream was accepted by ZFS, not that Narjar's published pairs are
complete. Restore validation remains an application-level `doctor`,
`reconcile --verify-hashes`, `verify`, and fresh-client substitution sequence.

Run a pool scrub separately from Narjar verification and retain the final pool
status output. Scrub checks and, where configured, repairs ZFS block checksums;
it does not validate narinfo signatures or NAR hashes.

~~~sh
set -euo pipefail
zpool scrub "$pool"
while zpool status "$pool" | grep -q "scan: scrub in progress"; do
  sleep 5
done
zpool status -v "$pool"
zfs get -H -o property,value \
  used,usedbysnapshots,referenced,logicalused,logicalreferenced,compressratio,quota,refquota,refreservation \
  "$dataset"
~~~

Report logical GC bytes, dataset referenced/logical bytes, compression ratio,
and snapshot-held bytes separately. A quota or reservation alert is a capacity
condition, not evidence that GC can reclaim the reported physical space. Release
the backup hold only after the external retention policy has made that snapshot
disposable.

~~~sh
zfs release -r narjar:backup "$dataset@$snapshot"
~~~

## Deletion and retention GC

`delete` supports offline logical deletion of one store hash:

1. Stop serve and acquire the exclusive lock.
2. Parse and validate the named narinfo.
3. Remove narinfo and sync DATA.
4. Leave its NAR untouched.
5. Run list-orphans or verify.

This instantly makes the store path absent while avoiding shared-NAR races.
Clients may retain positive narinfo cache entries until refresh/TTL and then
receive a NAR 200 if they already know its URL; therefore deletion is not a
confidential-erasure feature.

`gc` is the bounded offline retention operation. It validates the entire
published inventory before planning or deleting, protects the transitive
`References` closure of configured roots, and orders eligible narinfos by
publication time. Its size accounting is logical file length, so snapshots,
compression, reflinks, CoW, and sparse allocation remain filesystem/operator
concerns. NARJ-32 rejects access-time retention, online GC, a
resident worker, and an HTTP delete/GC API.

## Observability

Startup, recovery, and command failures produce diagnostics on stderr. Narjar
does not emit structured per-request logs, assign request identifiers, or provide
a configurable store-hash logging mode. Use the HTTP metrics for aggregate
request counts, byte counts, outcomes, and durations. If a reverse proxy logs
individual requests, configure it to redact credentials.

GET /healthz is unauthenticated and returns 200 once the HTTP loop is alive.
It says nothing about disk writability or trust configuration.

GET /readyz returns 200 only when the process lock is held, layout and
nix-cache-info are valid, trusted keys are loaded, read access works, and free
space exceeds reserve. It returns 503 with a bounded reason class otherwise.
In private-read mode it requires read authorization; public-read mode leaves it
public.

GET /metrics exposes Prometheus text generated directly from atomic counters,
without a metrics crate. Private-read mode requires read authorization.
`narjar stats` fetches and prints that same exposition; it has no JSON output
mode, and `/metrics` is the only statistics route.
Required series:

- `narjar_http_requests_total{method,route,status}` uses fixed method and route
  values, plus exact supported HTTP status codes and `other`.
- `narjar_http_upload_declared_bytes_total` counts declared upload body bytes;
  `narjar_http_upload_received_bytes_total` counts upload body bytes actually
  consumed, including bytes consumed before a failed or truncated upload.
  `narjar_nar_upload_validated_logical_bytes_total` counts logical bytes only
  after the complete encoded upload and decoded hash/size validation succeeds;
  it does not claim NAR grammar or signature validation.
  `narjar_nar_upload_committed_logical_bytes_total{outcome}` counts logical
  bytes at durable canonical publication, separating newly created payloads
  from identical duplicates. These are storage-boundary counters, not HTTP
  declared/received bytes or output-format conversion counts.
  `narjar_http_bytes_out_total` counts NAR and narinfo body bytes actually
  accepted by socket writes/sendfile, including partial progress before a
  failed delivery. It excludes control endpoints, response headers, TLS, and
  HEAD bodies; it does not prove that the client application received them.
  `narjar_response_transfer_failures_total{kind}` classifies failed response
  writes as `timeout`, `disconnected`, or `other`; this bounded cause counter
  complements the selected HTTP status and partial-body byte total. Request
  header and upload-body read timeouts/disconnects are counted in
  `narjar_connections_total`.
- `narjar_auth_failures_total{scope}` uses only `read` and `write` scopes.
- `narjar_validation_failures_total{class}` uses only `body`, `nar`, and
  `narinfo` classes.
- `narjar_nar_range_requests_total{method,outcome}` counts parsed range
  decisions for existing NARs: `full`, `partial`, `unsatisfiable`, and
  `invalid`. GET and HEAD remain separate; status 416 separately identifies
  unsatisfiable responses.
- `narjar_uploads_in_flight` and `narjar_requests_in_flight` are RAII gauges
  and return to zero after each request completes.
- `narjar_temp_objects` is the current process's temporary-publication count;
  it is updated at create/remove boundaries and does not perform an online
  cache inventory. Temporary files left by an earlier process are not included.
- `narjar_disk_full_total` and `narjar_capacity_failures_total{reason}` use
  fixed `no_space`, `quota`, `inodes`, and `read_only` reasons.
- `narjar_publications_total` and the
  `narjar_publication_duration_seconds` count/sum/max summary cover each
  publication attempt.
- `narjar_storage_capacity_bytes{kind}` and
  `narjar_storage_capacity_inodes{kind}` report `total` and `available`
  values from `statvfs` on the NAR destination; `narjar_storage_read_only`
  reports its read-only flag. These are O(1) descriptor queries and omit the
  series when the destination probe fails.
- `narjar_cache_population_narinfo_claimed_nar_bytes` sums structurally valid
  `NarSize` claims once per store path. Shared NAR content contributes once
  for each store path; this is distinct from stored raw-file bytes and is not
  signature verification.
- `narjar_cache_population_scan_started_timestamp_seconds` and
  `narjar_cache_population_scan_timestamp_seconds` bracket the most recent
  scan attempt; `narjar_cache_population_scan_duration_seconds` uses monotonic
  elapsed time. `narjar_cache_population_sample_timestamp_seconds` is the
  completion time of the last complete aggregate.
- `narjar_cache_population_scan_entries`,
  `narjar_cache_population_scan_ignored_entries`,
  `narjar_cache_population_scan_disappeared_entries`, and
  `narjar_cache_population_scan_errors` describe traversal coverage;
  `narjar_cache_population_scan_narinfo_read_errors` isolates unreadable
  metadata among those errors.
  `narjar_cache_population_scan_quality{quality}` uses only `complete`,
  `changed_during_scan`, `entry_errors`, or `failed`.
- `narjar_cache_population_narinfo_entries{kind}` separates structurally
  parsed, malformed-filename, malformed-content, and unreadable narinfo
  entries from the last complete aggregate.
  `narjar_cache_population_refresh_failed` is 1 after an incomplete or failed
  attempt; its coverage and quality describe that attempt while the previous
  complete aggregate remains available with stale state.
- Optional ZFS observations use `narjar_zfs_bytes{kind,state}` for used,
  logical, referenced, snapshot, child, reservation, and available byte totals.
  `narjar_zfs_compression_info{algorithm,state}` has fixed algorithm values;
  `narjar_zfs_compression_level{algorithm,state}` reports numeric levels
  separately, and unknown future settings use `algorithm="other"`.
- narjar_ready 0/1

The [`health_readiness_metrics_and_stats_follow_the_operator_contract`](../tests/cli.rs)
integration test exercises the metric output and readiness transitions; the
metric implementation is in [`src/metrics.rs`](../src/metrics.rs).

Labels are fixed enums; no request IDs, paths, token names, or hashes become
metric labels.

Explicit `gc`, `reconcile` (including structural inspection/cleanup), and
`verify` commands persist a bounded last-run summary in the cache directory.
`/metrics` samples those summaries without running maintenance itself. A
started timestamp with no completion is reported separately, so an interrupted
operation cannot replace or refresh the last completed result. Inventory
classes are exported as fixed labels. GC-reclaimed bytes are Narjar's logical
accounting delta, not a claim about physical blocks freed; unmeasured byte
counts are omitted.

The following measurements are omitted. Client-side push
preflight and trusted-cache skips cannot be inferred from server requests.
Upstream edge-fill outcomes, native-source lease counts, and online-retention
effects belong with those features when implemented. Per-object popularity and
distinct-client counts are omitted to avoid a resident catalog, privacy
exposure, and unbounded metric cardinality. Build-time savings and host-level
ARC, disk, and network pressure belong in client or platform monitoring. These
omissions mean "not measured," not zero.

## Filesystem support boundary

Narjar's required filesystem contract is limited to regular files and
directories, no-follow path checks, file and directory sync, same-filesystem
no-replace hard links, unlink, enumeration, and an exclusive local lease. The
service does not detect or configure a filesystem-specific backend.

Linux chunked storage additionally requires `syncfs` to make newly linked
chunks durable before manifest publication. Darwin/APFS has a native package
and test lane for flat storage; host-specific crash-durability guarantees remain
unverified. See the [filesystem capability ADR](filesystem-capability-adr.md)
for backend-specific durability requirements and remaining conformance gaps.

| Environment | Current classification | Meaning |
| --- | --- | --- |
| NixOS module evaluation | configuration only | Covers module options and generated units, not filesystem or service runtime behavior. |
| XFS, btrfs, ZFS, and Darwin APFS | unverified host-specific behavior | Do not turn successful unit tests or a deployment anecdote into a support guarantee. |
| tmpfs | non-persistent fixture only | Useful for tests; it is not a durable cache or a backup target. |
| bind-mounted DATA | depends on the mounted underlying filesystem | Validate the mounted DATA path and its ownership; the container/image filesystem is not the storage contract. |
| overlay, NFS, SMB, and FUSE | unsupported or unverified | Do not use them for a claimed production deployment without a conformance result for link, lock, sync, and transaction-recovery semantics. |

For a Narjar-only ZFS dataset, the conservative provisional posture is
`sync=standard`, checksums enabled, `dedup=off`, `atime=off`, the default record
size and cache topology, and no special vdev or SLOG requirement. The
[filesystem capability ADR](filesystem-capability-adr.md#support-boundary) and
[architecture](architecture.md#canonical-storage-backends) recommend
`compression=zstd` (the OpenZFS alias for `zstd-3`). Narjar does not set or verify
ZFS properties. This recommendation does not establish a speed, space-saving,
or filesystem-conformance guarantee. Other compression levels, non-default
recordsize, ARC policy, deduplication, and other tuning remain optional and
unapproved until the corresponding measured evidence exists. `sync=disabled`
violates the durability contract.

## Graceful shutdown

SIGINT/SIGTERM set a shutdown flag, stop admitting new requests, and wait up to
the configured grace period for workers. The drain order is deterministic:

1. Publication admission changes from open to draining before the listener
   closes. This drops the queue's only sender; no later publication can enter it.
2. Accepted request workers finish or reject their current requests. Idle
   keep-alive connections close without waiting for the full I/O timeout, and
   persistent connections cannot start another request during shutdown.
3. Publication workers drain already queued uploads and finish any narrow
   destination commit they have begun. Request and publication workers share
   the same grace deadline.

In-flight uploads and queued publications may finish within the grace period;
transaction records make any interruption before a durable boundary
reconcile-safe. After the deadline, process termination leaves only recorded
transactions, reconcile-safe temporaries, or already durable immutable files.
A second signal exits immediately. The NixOS module defaults systemd
`TimeoutStopSec` to `shutdownGraceSeconds + 10`. An explicit
`systemd.services.narjar.serviceConfig.TimeoutStopSec` overrides that default.
For other systemd deployments, set the stop timeout above the grace period
with a supervisor margin so the service can drain before being killed.

Implementation may use signal-hook as the one justified signal dependency.
There is no control socket.

## Deployment

The flake exports one implementation in three deployment forms:

- `packages.x86_64-linux.narjar-static` is the musl binary. The
  `static-elf` check rejects an ELF interpreter or dynamic `NEEDED` entry.
- `nixosModules.default` runs the normal package as a hardened systemd
  service.
- `packages.x86_64-linux.narjar-oci` is an OCI archive containing that same
  static binary, an unprivileged numeric user, and the `/var/lib/narjar`
  layout.

A minimal NixOS configuration is:

~~~nix
{
  imports = [ inputs.narjar.nixosModules.default ];

  services.narjar = {
    enable = true;
    listen = "127.0.0.1:5000";
    workers = 8;
    maxInFlight = 64;
    maxNarBytes = 16 * 1024 * 1024 * 1024;
    minFreeBytes = 1024 * 1024 * 1024;
    shutdownGraceSeconds = 30;

    auth.trustedPublicKeys = "/run/keys/narjar-trusted-public-keys";
    auth.readTokens = "/run/keys/narjar-read-tokens";
    auth.writeTokens = "/run/keys/narjar-write-tokens";
  };
}
~~~

Scheduled retention is disabled unless explicitly enabled. On NixOS, the optional
timer runs a one-shot offline pass with the same data-directory lock as the
server:

~~~nix
services.narjar.gc = {
  enable = true;
  schedule = "*-*-* 03:00:00";
  maxBytes = 8 * 1024 * 1024 * 1024;
  targetBytes = 6 * 1024 * 1024 * 1024;
  minAgeSeconds = 7 * 24 * 60 * 60;
  protectedRoots = "/var/lib/narjar/protected-roots";
};
~~~

`maxBytes` starts collection above its limit and is also the target when
`targetBytes` is unset. When both are set, `targetBytes` must not exceed
`maxBytes`.

Enabling this creates `narjar-gc.timer` and `narjar-gc.service`. The service
stops `narjar.service`, runs `gc --apply`, and starts the cache again from
`ExecStopPost`, including after a failed collection. A persistent timer may
run once after downtime; it is still disabled by default, and at least one
size or age policy must be configured. The maintenance interval is expected
downtime, so schedule it alongside storage snapshots and backups.

For OCI or other non-systemd deployments, use the equivalent explicit
stop/collect/start sequence:

~~~sh
docker stop narjar
narjar gc --data-dir /var/lib/narjar --target-bytes 6442450944 --min-age-seconds 604800 --apply
docker start narjar
~~~

Do not run GC while another process has the data-directory lease. If a pass is
interrupted, leave the recovery marker in place and start Narjar; startup
revalidates the inventory before serving.

The auth values are host paths consumed by systemd `LoadCredential`, not
credential contents. Do not use `builtins.readFile` or Nix string literals for
secrets. On each activation, configured credentials are copied to a
same-directory temporary file, synced, atomically renamed into place, and the
parent directory is synced. A failed replacement therefore leaves the old
complete file. `readTokens = null` removes the managed read-token file;
`writeTokens = null` and `trustedPublicKeys = null` preserve their
operator-managed files. systemd supplies a dynamic unprivileged user, a mode-0700
`StateDirectory`, and the only writable path. The unit drops capabilities and
enables `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, kernel and
namespace protections, and an AF_INET/AF_INET6-only address-family allowlist.
The module also sets `RequiresMountsFor` for the configured data path. On the
tested native-ZFS deployment this resolves to the generated
`var-lib-narjar.mount` unit; filesystems whose mount integration does not
provide a path mount unit must supply an administrator-owned readiness
dependency. Narjar never mounts or creates the dataset.
The `module-evaluation` check covers generated service configuration and valid
and invalid `dataDir` declarations. CI does not boot NixOS VMs, so it does not
verify service activation under systemd hardening. There is currently no dedicated
block-device, tmpfs, unmount/remount, or cross-filesystem conformance lane. XFS, btrfs, ZFS,
overlay, bind-mount variants, quota/inode exhaustion, read-only remounts, and
Darwin APFS remain unverified until host-specific lanes provide those fixtures;
they must not be advertised as covered by the portable checks.

`GET /healthz` is the liveness endpoint. `GET /readyz` is the readiness
endpoint and requires a read token when private-read mode is enabled. Socket
activation is an explicit v0.1 non-goal because Narjar owns the listener.

For public service, terminate TLS and enforce stream timeouts at a reverse
proxy. For example:

~~~nix
services.nginx = {
  enable = true;
  virtualHosts."cache.example.org".extraConfig = "client_header_timeout 10s;";
  virtualHosts."cache.example.org".locations."/" = {
    proxyPass = "http://127.0.0.1:5000";
    extraConfig = ''
      proxy_request_buffering off;
      proxy_buffering off;
      client_max_body_size 16g;
      client_body_timeout 300s;
      proxy_read_timeout 300s;
      proxy_send_timeout 300s;
    '';
  };
};
~~~

Build and load the OCI archive with any OCI-capable runtime:

~~~sh
image="$(nix build --print-out-paths .#narjar-oci)"
podman load --input "$image"
install -d -m 0700 -o 65532 -g 65532 /var/lib/narjar-container
podman run --rm --read-only \
  --user 65532:65532 \
  --publish 127.0.0.1:5000:5000 \
  --volume /var/lib/narjar-container:/var/lib/narjar \
  narjar:latest
~~~

The archive sets only the standard image entrypoint, command, user, port,
working directory, and volume metadata. TLS, credentials, and bind mounts remain
orchestrator concerns; Narjar does not inspect a Docker-specific environment.
