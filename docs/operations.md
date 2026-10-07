# Narjar operations

## CLI

Run `narjar <command> --help` for flags and defaults. Non-secret options use
command-line flags first, then their documented `NARJAR_*` environment
variables, then compiled defaults. There is no configuration file.

`narjar setup` creates a cache and producer credentials; see the
[README](../README.md#create-a-cache). To provision them separately, run this
example in Bash as the cache owner:

~~~sh
set -euo pipefail
umask 077
install -d -m 0700 /var/lib/narjar
install -d -m 0700 /run/narjar-credentials
narjar init --data-dir /var/lib/narjar
narjar token create --data-dir /var/lib/narjar --scope write --name ci > /run/narjar-credentials/narjar-ci-token
narjar key generate --name narjar-producer --secret-key-file /run/narjar-credentials/narjar-producer.sec --public-key-file /var/lib/narjar/narjar-producer.pub
install -m 0600 /var/lib/narjar/narjar-producer.pub /var/lib/narjar/trusted-public-keys
narjar serve --data-dir /var/lib/narjar --listen 127.0.0.1:5000
~~~

Files under `/run` disappear on reboot. Retain the producer secret and upload
token in protected persistent storage. The server needs public signing keys,
not the producer secret.

`token create` prints the secret once and stores only its hash and label.
Redirect stdout to a private file. `token revoke` removes a label. These are
offline commands: stop the server before changing its token files. Use a
mode-`0600` netrc file for HTTP credentials, not command-line secrets.

A write token permits uploading; it does not authorize signing. Narinfo must
carry a signature from a key in `trusted-public-keys`. To rotate signing keys,
trust both public keys while producers switch, then remove the old key once
clients no longer need its cached signatures.

### Local Nix store access

`push` accepts concrete `/nix/store/...` paths, reads the Nix SQLite metadata
database, and walks their dependency closure. Dependencies upload first;
independent paths upload in parallel up to `--jobs` (default `1`).
It serializes NARs and signs metadata without Nix subprocesses or changes to
the store database.

The client roots the requested paths before reading closure metadata. With
writable Nix state it registers temporary roots in
`$NIX_STATE_DIR/temproots/<pid>` (default `/nix/var/nix/temproots/<pid>`)
and keeps that file locked. It holds Nix's `gc.lock` only while registering
roots and reading metadata, not throughout the transfer. Otherwise it uses
`AddTempRoot` over the Nix daemon socket and keeps the connection alive.
Rooting failures abort the push.

`--compression` controls upload transport only. HTTP requests have a
30-second total timeout by default; set `--timeout-seconds` for longer
transfers. Netrc credentials require HTTPS unless `--insecure-http` is
explicitly supplied. An unauthenticated HTTP request remains unauthenticated
after a redirect to HTTPS.

A valid destination publication for the same full store path is skipped,
even if local NAR contents differ. `--refresh` bypasses that check but cannot
replace immutable metadata. A concurrent publication of the same path is
also destination-present. Other destination narinfo conflicts fail unless
`--ignore-conflicts` is set. Payload upload failures still abort.

`--trusted-upstream` and `--trusted-upstream-key` check signed metadata
before uploading. They do not fetch upstream payloads; consumers must have
that upstream configured as a substituter. Failed checks fall back to local
upload. `--refresh` bypasses upstream checks.

The server does not serve the native Nix store. Push requires a local Nix
store, but serving an initialized Narjar cache does not require Nix.

## Storage and permissions

Choose `flat` or `chunked` at initialization and pass the same
`--storage-backend` to serving and maintenance commands. Flat is the
default and works on Linux and macOS; chunked is Linux-only. The layout
descriptor fixes the backend for that data directory. There is no migration
or automatic conversion.

Keep DATA private to the cache owner: directories `0700`, published files,
token hashes, trusted keys, and the lock `0600`. Producer secrets belong
outside DATA. Generated public key files can be distributed separately.
The reverse proxy must not read DATA directly.

Flat storage keeps canonical raw NARs in `nar/`. Chunked storage keeps
canonical manifests and shared chunks in `.narjar-manifests/` and
`.narjar-chunks/`. Compressed ingress receipts in `.narjar-ingress/`
bind upload identities to canonical raw identities; egress receipts in
`.narjar-egress/` bind raw identities to generated compressed downloads.
Preserve these along with `.narjar-layout` and the recovery records.

The daemon creates a private `.narjar-control/gc.sock` for local online GC.
It is not an HTTP endpoint and does not need proxy configuration.

See the [filesystem requirements](https://github.com/mjc/narjar/blob/main/docs/filesystem-capability-adr.md) for
publication and synchronization requirements. Narjar does not manage
filesystems or ZFS properties. Logical byte totals do not measure physical
space used under compression or snapshots.

## Capacity and timeouts

The server uses bounded request and publication queues. `--max-in-flight`
includes queued requests and idle keep-alive connections; excess admission
receives 429 when a response can be sent. Idle connections do not occupy a
request worker.

Uploads have separate encoded-size, decoded-size, and decoder-memory limits.
A small I/O buffer does not bound decoder memory. At most `--workers`
compressed uploads decode simultaneously; other worker buffers, chunk batches,
and connection state add to memory use.

Staging reserves disk capacity before writes, including decoded expansion and
generated compressed output. The free-space reserve and inode checks cannot
prevent an external writer from exhausting the filesystem.

`--io-timeout-seconds` is an idle-progress deadline for individual socket
reads and writes, not a total transfer deadline. The default is 30 seconds.
A large transfer may take longer while continuing to make progress.

Capacity failures return 507 for space, quota, or inode exhaustion, and 503
for read-only storage. Unexpected I/O and synchronization failures return 500.
A failure after response headers are sent closes the connection instead of
changing its status.

SIGINT and SIGTERM stop admission and drain active collection and request/publication workers up to
`--shutdown-grace-seconds` (default 30). A second signal exits immediately.
The NixOS module's default stop timeout is the grace period plus 10 seconds.
Systemd waits for the daemon's readiness notification before starting dependent
units, including online GC. Startup recovery has a one-hour service timeout.

## Recovery and maintenance

Serving and offline maintenance take the same exclusive DATA lock. Stop the server
before running offline commands:

~~~sh
narjar doctor --data-dir /var/lib/narjar --json
narjar reconcile --data-dir /var/lib/narjar --verify-hashes
narjar verify --data-dir /var/lib/narjar
narjar cleanup --data-dir /var/lib/narjar --min-age-seconds 86400
~~~

`reconcile` reports metadata, signatures, payload availability, and orphans.
`--verify-hashes` reads payload content as well. `--structural` instead inspects
directory entries and temporary files. `--limit` caps retained findings and
causes failure if exceeded; it does not bound traversal work.
`--min-age-seconds` classifies temporary files as young or stale.
`verify` performs content verification and exits unsuccessfully for invalid
published pairs. `cleanup` removes eligible stale temporary files; it does
not publish orphans or repair invalid metadata. Reconcile and verify do not
repair cache objects, but do write maintenance start/completion summaries.

A successful NAR PUT makes canonical content durable. A successful narinfo
PUT publishes the store path only after its payload and metadata are durable.
An interrupted upload can leave an orphan payload or temporary files, but
must not leave metadata pointing to an uncommitted payload.

Startup checks the fixed layout. If recovery is marked, it validates trusted
published references using file types and sizes, manifests, and chunk
availability; it does not hash every payload. Invalid references stop startup.
Recorded temporary resources are cleaned before the clean marker is restored.
Use offline verification to detect same-size corruption.

Compressed ingress metadata requires its matching receipt. If that evidence
is missing, upload the payload again. For server-generated compressed output,
a valid receipt survives a missing or corrupt derivative while the canonical
source exists. Repair must reproduce its recorded encoded identity. Ordinary
uploaded content and narinfo remain immutable.

### Retention

`delete --store-hash HASH` removes a publication's metadata, not its payload.
Clients holding cached narinfo can still fetch that payload until GC removes
it. `list-orphans` reports unreferenced canonical objects.

GC defaults to a dry run:

~~~sh
narjar gc --data-dir /var/lib/narjar --target-bytes 6442450944 --dry-run --json
narjar gc --data-dir /var/lib/narjar --target-bytes 6442450944 --apply --json
~~~

For age-based retention, use the same period syntax as `nix-collect-garbage`:

~~~sh
narjar gc --online --data-dir /var/lib/narjar --delete-older-than 7d --dry-run --json
narjar gc --online --data-dir /var/lib/narjar --delete-older-than 7d --apply --json
~~~

`7d` means seven 24-hour days. Age is measured from narinfo modification time
for publications and payload modification time for orphans, not last access.
Protected roots, minimum age, and online grace still apply. The seconds-based
`--max-age-seconds` option is mutually exclusive with `--delete-older-than`.
The NixOS module exposes this as `services.narjar.gc.maxAgeDays = 7`.

`--online` asks the running daemon to collect. Run it
as the cache owner and pass the configured storage backend. The command fails
if no daemon is running, the collector is busy, or the backend differs. Online
mode never stops the server or falls back to offline collection.

Linux uses a descriptor-relative socket address, so long data-directory paths
work. On macOS, the control socket pathname must fit the platform's Unix socket
limit. If it does not, the daemon reports that online GC is unavailable and
continues serving; offline maintenance still works with the server stopped.

Online GC supports flat and chunked storage. Inventory and chunk marking run
without excluding publication. Mutations invalidate the scan before deletion.
New advertisements defer deletion only when they protect a selected object or
its dependent publication. Active uploads and binding can return busy; a
chunked read defers only retirement of its own canonical object. Unrelated
metadata and payload reads do not block collection. Retry a deferred command later.
During deletion, reads of retained objects continue. Retiring metadata returns
a miss; already-open flat transfers finish through their descriptors.

Online collection enforces at least ten minutes of age protection. Accepted
canonical uploads and successfully advertised narinfos get a ten-minute grace,
including the advertised publication's transitive dependencies. Protection is
renewed after metadata delivery. The daemon retains at most 4096 recent object
keys; overflow protects all objects for the grace instead of dropping live
protection. Startup also protects all objects for ten minutes because previous
advertisements are not retained in memory. A size target does not override
these protections. Cached metadata does not guarantee payload availability
after the grace expires.

Online GC does not perform offline recovery or clear publication journals.
Unresolved publication records defer collection. Failed or interrupted deletion
leaves recovery evidence for restart or offline maintenance.

GC validates published inventory before deleting anything and selects
publications by narinfo modification time. `--min-age-seconds` protects recent
publications and orphans. `--protected-roots` takes store paths or hashes,
one per line, and retains their transitive references.

Apply removes and syncs metadata before reclaiming payloads. Shared raw files
and chunks survive while referenced by a remaining publication.
Reports use logical file lengths, not physical space freed. Compression,
snapshots, and shared payloads affect actual reclamation.

### Backup and restore

Stop the server and copy the complete DATA directory with ownership and
permissions preserved. Include canonical objects, manifests/chunks, receipts,
published metadata, credentials, layout, and recovery records. Do not copy
only `nar/` or only the chunk directory.

On the restored root, run `doctor`, `reconcile --verify-hashes`, and `verify`
before serving, then check `/readyz`. Keep the restored copy private:
`auth/` and `trusted-public-keys` define its authorization and trust policy.
Filesystem snapshots and replication are managed outside Narjar.

## Observability

`GET /healthz` is public liveness. `GET /readyz` probes the staging filesystem's
free bytes, inodes, and read-only status against the configured reserve; it
returns 503 when that probe fails. Layout and trust checks happen at startup,
not on each readiness request.
`GET /metrics` returns Prometheus text; `narjar stats --url URL` prints the
same response. Readiness and metrics require read credentials in private-read
mode. There is no separate JSON statistics route.

Metrics include cache hits/misses/failures by object type and method; request
and connection outcomes; transferred bytes; request/publication durations;
process memory and CPU; storage capacity; queue depth; and maintenance results.
`narjar_online_gc_requests_total` distinguishes successful passes, unmet targets,
contention, invalidated inventory, and failures. Existing maintenance series
report the last pass's duration and logically reclaimed objects and bytes.
The exposition's HELP text describes each series. Labels do not contain
paths, hashes, token names, or request IDs.

Hit ratio is hits divided by hits plus misses; failures are separate.
Counters reset on restart. Outgoing bytes count successful socket writes,
including partial responses; they do not prove receipt by the client.
Logical-byte counters do not measure filesystem compression or physical disk
use.

Population sampling is disabled by default. Enable it with
`--stats-inventory-interval-seconds 900`; metrics requests use the last sample
rather than scanning the cache. Sample timestamps, quality, and stale state
distinguish a complete sample from a failed refresh. ZFS samples come from an
external file or the NixOS module's optional sampler, not a subprocess launched
by the server.

Diagnostics go to stderr. Narjar has no per-request structured log or request
identifier. Configure proxy logs to redact credentials.

## Deployment

The [NixOS module](https://github.com/mjc/narjar/blob/main/nix/module.nix) initializes the cache and runs it under an
unprivileged user. Its `auth.*` options take host file paths loaded through
systemd credentials; do not put secret contents in Nix expressions.
`auth.writeTokens` must contain Narjar's hashed token records, not a plaintext
token. See the [README example](../README.md#nixos-service).

Scheduled online GC is disabled by default:

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

The GC unit requests collection through the running daemon; it does not stop
or restart the service. `maxBytes` starts collection above that limit and supplies the
target if `targetBytes` is unset. When both are set, the target must not exceed
the maximum.

The flake also provides a static Linux binary and an OCI archive. Initialize
the persistent data mount and install credentials before serving. The image
runs as UID/GID 65532; arrange matching mount permissions. It does not include
a reverse proxy or provision upload credentials.

For remote use, terminate TLS at a reverse proxy. Preserve Content-Length and
Authorization, disable PUT request buffering, and align body limits and
timeouts with Narjar. Restrict the direct HTTP listener to loopback or a trusted
network. Socket activation is not supported.
