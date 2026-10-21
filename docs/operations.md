# Narjar operations

## CLI

Run `narjar <command> --help` for flags and defaults. Non-secret options use
command-line flags first, then the documented `NARJAR_*` environment
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
private netrc file for HTTP credentials, not command-line secrets (`0600` on Unix).

A write token permits uploading, not signing. Narinfo must
carry a signature from a key in `trusted-public-keys`. To rotate signing keys,
trust both public keys while producers switch, then remove the old key once
clients no longer need its cached signatures.

### Windows

Use flat storage on local NTFS. Install the MSVC Rust toolchain and Windows SDK
to build with Cargo; the installed cache server does not need Nix or SQLite.
The executable uses the Microsoft Visual C++ runtime (`VCRUNTIME140.dll`).
Install the Visual C++ Redistributable when moving it to a machine without that runtime.
`push` and native-store serving require Unix. A Windows cache accepts the same
HTTP uploads and serves raw, XZ, or Zstd output.

In PowerShell, create the cache and its credentials, then run the server:

~~~powershell
narjar setup --yes --data-dir ./cache --credentials-dir ./credentials
narjar serve --data-dir ./cache --listen 127.0.0.1:5000
~~~

Setup does not start the server. Use Ctrl+C to stop it. Keep credentials outside
DATA and restrict their DACLs to the cache account, SYSTEM, and Administrators.
Narjar creates these permissions during setup and rejects unsafe existing files.

Online GC runs over a private named pipe bound to the account and opened DATA
directory. Run it as the cache owner; there is no TCP maintenance listener.

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

`--compression` controls upload transport only. Native HTTP requests have a
30-second DNS/connect and network inactivity timeout by default; set
`--timeout-seconds` to change it. Transfers can take longer while making
progress. Netrc credentials require HTTPS unless `--insecure-http` is
explicitly supplied. An unauthenticated HTTP request remains unauthenticated
after a redirect to HTTPS.

Push skips a valid destination publication for the same full store path,
even if local NAR contents differ. `--refresh` bypasses that check but cannot
replace immutable metadata. If another uploader publishes that path first,
push counts it as already present. Other destination narinfo conflicts fail
unless `--ignore-conflicts` is set. Payload upload failures still abort.

`--trusted-upstream` and `--trusted-upstream-key` check signed metadata
before uploading. They do not fetch upstream payloads; consumers must have
that upstream configured as a substituter. Failed checks fall back to local
upload. `--refresh` bypasses upstream checks.

Push and native-store serving require a local Nix store. Serving an initialized
standalone Narjar cache does not require Nix.

## Read-through edge

Run a local read-through cache when clients need to keep building during a
central cache outage. Initialize a Narjar data directory and install the central
cache's public signing keys in `trusted-public-keys`, then run:

~~~sh
narjar serve --data-dir ./edge --listen 127.0.0.1:5000 \
  --serve-source read-through --edge-upstream https://cache.example \
  --edge-max-fills 4 --edge-timeout-seconds 30
~~~

Configure Nix to use the local URL, not the central cache URL. Push directly to
the central cache. The local cache is read-only and rejects PUT requests without
reading their bodies. It needs neither Nix executables nor a Nix database. Use
`narjar doctor --data-dir ./edge` for local storage diagnostics; it does not
probe the upstream. `doctor` also accepts `--serve-source read-through` or
`NARJAR_SERVE_SOURCE=read-through` for those local storage checks.

A local miss downloads the upstream narinfo, verifies its signature, then
downloads and verifies the NAR it names. The NAR, rewritten narinfo and retention
record must be written and synced to disk before the request succeeds. Downloads
can be uncompressed, XZ or Zstd; the local cache always serves uncompressed NARs.
Concurrent requests for the same object share the download. Redirects are
rejected, and NAR downloads must use paths under the configured upstream URL.
Use a separate data directory for this mode. It does not serve, overwrite or
migrate existing compressed publications.

An upstream 404, timeout, refused connection, 429/503, invalid signature or
incomplete/corrupt payload produces a local narinfo 404. Nix can then build a
path for which it has a build recipe, even with `fallback = false`. A local hit
needs no upstream connection. Downloading a path does not download all its
dependencies. If a dependency is unavailable, Nix can build it and the paths that
depend on it locally, provided it has their build recipes. A cache miss cannot
make a path buildable when Nix has no recipe for it.

### Limits and timeouts

The existing size, decoder-memory, staging-space and minimum-free controls
apply to upstream downloads. `--edge-max-fills` limits concurrent downloads;
additional misses for unrelated objects return 404. Requests downloading or
waiting for an object can use at most `min(--workers, --max-in-flight) - 1`
request slots. This leaves a worker and a connection available for local hits,
NAR downloads and health requests. This mode requires both `--workers` and
`--max-in-flight` to be at least two.

`--edge-timeout-seconds` limits connection setup, idle network I/O and the time
a request can wait for another request's download. A download that keeps making
progress can run longer. `--edge-fill-timeout-seconds` limits the total download
time and defaults to 3600 seconds; increase it for large NARs on slow links.

`--edge-negative-ttl-seconds` sets how long the local cache remembers upstream
misses and failures. It defaults to one second; values above 60 use 60 seconds.
The number of cached failures is also limited. Nix caches missing narinfo
separately, so a long client negative TTL can delay retries after recovery.

### Retention and client caching

Before returning narinfo, Narjar saves a keep-until time, called a lease, under
`.narjar-advertisements`. Each narinfo read extends the lease. Online and offline
GC must retain the metadata and NAR until that time, including after a restart.
If space runs out, new downloads fail rather than deleting leased data.

The default lease is 5,187,600 seconds: 60 days plus one hour. This covers two
of Nix's default 30-day positive-cache periods because loading narinfo from its
disk cache can start another full in-memory cache period. HTTP `no-store` does
not control these Nix caches. If you shorten the lease, shorten the client TTLs
as well and allow time for queued NAR requests. After a lease expires, GC can
delete a NAR even if a paused client still has its narinfo. Do not manually
delete cache data while clients may still use cached narinfo.

### NixOS

The module can configure both the loopback service and Nix's substituter:

~~~nix
services.narjar = {
  enable = true;
  edge = {
    enable = true;
    upstream = "https://cache.example";
    trustedPublicKeys = [ "cache.example:BASE64_PUBLIC_KEY" ];
    configureClient = true;
    clientPositiveTtlSeconds = 300;
    clientNegativeTtlSeconds = 1;
    leaseSeconds = 3600;
  };
  gc = {
    enable = true;
    maxBytes = 20 * 1024 * 1024 * 1024;
    targetBytes = 15 * 1024 * 1024 * 1024;
  };
};
~~~

`configureClient` replaces Nix's substituter list with this loopback endpoint,
installs the same public keys for Nix, sets the TTLs, and keeps fallback disabled.
The module requires a lease of at least twice the positive TTL plus 300 seconds
to allow for delayed NAR requests. Public keys may be in the Nix store; no secret
signing key is needed. GC can leave the cache above its size target while leases
have not expired. `/metrics` reports local hits, upstream results, active
downloads and cached failures.

Run `nix run .#edge-e2e` on Linux to test builds with fallback disabled, reuse of
cached narinfo after a restart and offline GC, and recovery after an upstream
outage. The test uses private Nix stores; it does not change the host store or
boot a VM.

## Native-store serving

Select `serve --serve-source native-store` with explicit `--native-store-dir`,
`--native-state-dir`, `--native-roots-dir`, and `--native-min-lease-seconds`.
The source is read-only: GET, HEAD, and single ranges are supported; PUT returns
405 without accepting or queuing a body. Output must be raw and the Narjar
data directory must use the flat backend.
The HTTP source currently supports only `/nix/store`; other store roots are
rejected during configuration.

The service reads the existing SQLite database without writing to it. It needs
read access to the store and GC lock, plus write access to its private roots
directory at `STATE/gcroots/auto/narjar`. Keep that directory outside the store
and Narjar data directory. Do not remove it during restart: its leases protect
previously advertised paths. Expired leases are cleaned in bounded batches;
active deliveries retain their roots until delivery ends.
Payload hashes resolve through private advertisement records, not a scan of the
Nix database. Only a trusted narinfo advertisement creates that association.
The lease manager preserves it across restart and removes it with the expired
root; unknown payload hashes do not acquire leases.

`--native-signing-key-file` supplies a Nix-format secret key for unsigned paths.
Its public key must be trusted by the cache. Without a signer, only existing
trusted signatures are reused; unsigned or untrusted paths return 404. Metadata
or lease failures return 503 before a response body starts. Integrity failures
during delivery terminate the transfer and are recorded as failed responses.

NixOS example:

~~~nix
services.narjar = {
  enable = true;
  dynamicUser = false;
  auth.trustedPublicKeys = "/run/secrets/narjar-public-keys";
  nativeStore = {
    enable = true;
    signingKeyFile = "/run/secrets/narjar-secret-key";
    minLeaseSeconds = 5187600;
  };
};
~~~

The module prepares the roots with stable ownership, grants access to the GC
lock, and loads the signer through systemd credentials. It does not make the
store or metadata database writable. `doctor` accepts the same native source
and signing options as `serve`.

Nix caches positive narinfo independently of HTTP cache headers. The module's
5,187,600-second default covers two 30-day positive-cache windows plus an hour
for delayed requests. Match shorter leases to the client's configured TTL:
a 300-second positive narinfo TTL fits within a 3,600-second lease. Arbitrarily
suspended clients cannot be covered by a finite lease. Native responses require
HTTP metadata revalidation rather than advertising a year-long intermediary TTL.

`/readyz` checks the selected source's database, GC-lock access, lease state,
and free space on the roots filesystem, not unused upload staging. `/metrics`
reports `narjar_source_info`, registered native leases, expired leases released,
lease-capacity rejections, and failures by metadata/signature/lease/delivery/
cleanup phase. Existing request and transfer metrics include native reads.

## Storage and permissions

Choose `flat` or `chunked` at initialization and pass the same
`--storage-backend` to serving and maintenance commands. Flat is the
default and works on Linux, macOS, and local Windows NTFS; chunked is Linux-only. The layout
descriptor records the backend for that data directory; Narjar cannot convert
it to another backend.

Keep DATA private to the cache owner: on Unix, directories use `0700`, and
published files, token hashes, trusted keys, and the lock use `0600`. Windows
checks ownership and DACLs instead of permission bits. Producer secrets belong
outside DATA. Generated public key files can be distributed separately.
The reverse proxy must not read DATA directly.

Flat storage keeps canonical raw NARs in `nar/`. Chunked storage keeps
canonical manifests and shared chunks in `.narjar-manifests/` and
`.narjar-chunks/`. Compressed ingress receipts in `.narjar-ingress/`
bind upload identities to canonical raw identities; egress receipts in
`.narjar-egress/` bind raw identities to generated compressed downloads.
Preserve these along with `.narjar-layout` and the recovery records.

Unix daemons create a private `.narjar-control/gc.sock` for local online GC;
Windows daemons use an account-private named pipe. Neither is an HTTP endpoint
or needs proxy configuration.

See the [filesystem requirements](https://github.com/mjc/narjar/blob/main/docs/filesystem-capability-adr.md)
for publication and synchronization requirements. Narjar does not manage
filesystems or ZFS properties. Logical byte totals do not measure physical
space used under compression or snapshots.

## Capacity and timeouts

The server uses bounded request and publication queues. `--max-in-flight`
includes queued requests and idle keep-alive connections. When the limit is
reached, new requests receive 429 if a response can be sent. Idle connections
do not occupy a request worker.

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

SIGINT and SIGTERM stop accepting work and wait up to `--shutdown-grace-seconds`
(default 30) for active GC, requests, and publications to finish. A second signal
exits immediately.
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
directory entries and temporary files. `--limit` caps the number of findings
kept in the report and causes failure if exceeded; it does not limit how much
of the cache is scanned.
`--min-age-seconds` classifies temporary files as young or stale.
`verify` performs content verification and exits unsuccessfully for invalid
published pairs. `cleanup` removes eligible stale temporary files; it does
not publish orphans or repair invalid metadata. Reconcile and verify do not
repair cache objects, but do write maintenance start/completion summaries.

A successful NAR PUT makes canonical content durable. A successful narinfo
PUT publishes the store path only after its payload and metadata are durable.
Interrupted uploads can leave orphan payloads or temporary files, but not
published metadata pointing to an uncommitted payload.

Startup checks the fixed layout. If recovery is marked, it validates trusted
published references using file types and sizes, manifests, and chunk
availability; it does not hash every payload. Invalid references stop startup.
Recorded temporary resources are cleaned before the clean marker is restored.
Use offline verification to detect same-size corruption.

Compressed ingress metadata requires its matching receipt. If the receipt
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

### Scheduled retention

Scheduling is opt-in. The timer runs GC through the daemon without stopping it.
Size thresholds count logical cache bytes. Physical thresholds measure available
bytes on the data-directory filesystem, including the effects of compression and
snapshots. They are independent of the upload admission reserve.

~~~nix
services.narjar.gc = {
  enable = true;
  schedule = "hourly";
  randomizedDelaySeconds = 300;
  evictionOrder = "last-use";
  maxBytes = 8 * 1024 * 1024 * 1024;
  targetBytes = 6 * 1024 * 1024 * 1024;
  maxDeletions = 100;
  retryAttempts = 3;
  retryDelayMillis = 1000;
};
~~~

`last-use` orders pressure evictions by successful read resolution. It does not
change publication-age expiration. The module enables `serve --track-access`
when last-use scheduling is configured. Standalone servers must enable it
explicitly. Zero-byte records in `.narjar-access/` hold coarse timestamps;
repeated reads of cached keys are coalesced for an hour. Concurrent first reads
can write duplicate hints. The coalescing cache holds at most 4,096 keys.
Evicted keys can be recorded more often. Hints are not
synced per read and may be lost on a crash; reader pins, protected roots, and
advertisement grace do not depend on them. Missing or malformed hints fall back
to publication time; hint write or cleanup failures do not fail reads or GC.

For physical pressure, set `gc.minFreeBytes` and `gc.targetFreeBytes` together,
with a positive `gc.maxDeletions`. A bounded pass starts below the minimum and
subsequent scheduled passes continue toward the target. Reports contain measured
free space, not estimated reclaimed blocks. Snapshot-held space can leave the
target unmet after deletion. Measurements use the opened data-root filesystem,
not logical sizes or ZFS commands. `.narjar-gc-pressure` records an unfinished
cycle for the next pass and normal restarts. Changing the thresholds starts a
new cycle; reaching the target clears it. This advisory hint is best effort:
if it cannot be saved, the next pass can still start below the minimum. Dry runs
do not change the hint.

`maxDeletions` caps selected publications and orphans, not the initial inventory
scan, transfer size, or individual-object work. A chunked object may own many
chunks. Unfinished expiration is reported as `pending_expired`; a capped pass
can report `limit_reached`. An unmet target is not retried as a contention error.
Only Busy and Changed replies receive bounded retries. Transport and storage
errors are not retried after potentially ambiguous mutation.

`narjar_access_records_total{outcome="written|coalesced|failed"}` reports
access-hint recording. Existing online-GC metrics distinguish completed passes,
unmet targets, contention, changed inventories, and failures.

`--online` asks the running daemon to collect. Run it
as the cache owner and pass the configured storage backend. The command fails
if no daemon is running, the collector is busy, or the backend differs. Online
mode never stops the server or falls back to offline collection.

Windows derives its named-pipe address from the account and DATA identity, not
the pathname. Linux uses a descriptor-relative socket address, so long data-directory paths
work. On macOS, the control socket pathname must fit the platform's Unix socket
limit. If it does not, the daemon reports that online GC is unavailable and
continues serving; offline maintenance still works with the server stopped.

Online GC supports flat and chunked storage. Uploads can continue while GC
scans inventory and marks chunks. Changes to the cache invalidate the scan
before deletion. Serving narinfo defers deletion if it protects a selected
object or a publication that depends on it. Active uploads and narinfo binding
can make GC report busy. A chunked read defers deletion only for its own
canonical object; unrelated reads do not block collection. Retry deferred
collection later. Reads of retained objects continue during deletion. Metadata
being deleted returns a miss; already-open flat transfers finish through their
file descriptors.

Online GC never deletes objects younger than ten minutes. It also protects
accepted canonical uploads, successfully served narinfos, and their transitive
dependencies for ten minutes. Serving the metadata again renews that protection.
The daemon tracks at most 4096 recent object keys; if that limit is exceeded,
it protects all objects for the grace period. Startup protects all objects for
ten minutes because the daemon no longer has the previous process's record of
served metadata. A size target does not override these protections. Clients
with cached metadata may lose access to its payload after the grace expires.

Online GC does not perform offline recovery or clear publication journals.
Unresolved publication records defer collection. Failed or interrupted deletion
leaves recovery records for restart or offline maintenance.

GC validates published inventory before deleting anything and selects
publications by narinfo modification time. `--min-age-seconds` protects recent
publications and orphans. `--protected-roots` takes store paths or hashes,
one per line, and retains their transitive references. The CLI reads this file
before collection, including in online mode. Relative paths and `/dev/stdin`
refer to the invoking process, not the daemon. Sources are limited to 1 MiB;
online requests, including the validated roots, must fit the 16 KiB control
frame. Unreadable, invalid, and oversized inputs fail without collecting.

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

`GET /healthz` is a public liveness check. `GET /readyz` checks the staging
filesystem's free bytes, inodes, and read-only status against the configured
reserve; it returns 503 when that check fails. Layout and trust checks happen
at startup, not on each readiness request.
`GET /metrics` returns Prometheus text; `narjar stats --url URL` prints the
same response. Readiness and metrics require read credentials in private-read
mode. There is no separate JSON statistics route.

Metrics include cache hits/misses/failures by object type and method; request
and connection outcomes; transferred bytes; request/publication durations;
process memory and CPU; storage capacity; queue depth; and maintenance results.
`narjar_online_gc_requests_total` distinguishes successful passes, unmet targets,
contention, invalidated inventory, and failures. Existing maintenance series
report the last pass's duration and logically reclaimed objects and bytes.
Each series has HELP text describing it. Labels do not contain
paths, hashes, token names, or request IDs.

Hit ratio is hits divided by hits plus misses; failures are separate. A narinfo
hit means committed metadata was read successfully. Reads trust immutable disk
contents: they do not recheck signatures or backing payloads. Payload lookups
and transfers count their own failures. The ratio measures cache lookups, not
successful builds or payload integrity.

Counters reset on restart. Outgoing bytes count successful socket writes,
including partial responses; they do not prove receipt by the client.
Logical-byte counters do not measure filesystem compression or physical disk
use.

`narjar_build_info` identifies the version, storage backend and egress codec;
`narjar_stats_schema_version` identifies the metrics schema. Recent artifact
request and byte rates cover one- and five-minute windows and report how much
of each window was sampled. Requests to health, readiness, and metrics endpoints
are excluded. Full and range GET delivery durations have separate histograms;
HEAD and error responses are excluded. Interrupted transfers still count their
measured bytes and duration.

Process resources and filesystem capacity are sampled every five seconds.
`/metrics` reads the cached capacity sample, including its timestamp and state,
without probing the filesystem. Failed refreshes retain the last values as
stale and report readiness as unknown, not healthy. `/readyz` still checks the
filesystem on each request. Reported headroom can change before the next upload;
admission checks capacity separately. Connection, worker and queue gauges read
the current counts rather than periodic samples.

Population sampling is disabled by default. Enable it with
`--stats-inventory-interval-seconds 900`; metrics requests use the last sample
rather than scanning the cache. Use sample timestamps, quality, and stale state
to check for incomplete scans and failed refreshes. ZFS samples come from an
external file or the NixOS module's optional sampler, not a subprocess launched
by the server.

Diagnostics go to stderr. Narjar has no per-request structured log or request
identifier. Configure proxy logs to redact credentials.

## Deployment

The [NixOS module](https://github.com/mjc/narjar/blob/main/nix/module.nix)
initializes the cache and runs it under an unprivileged user. Its `auth.*`
options take host file paths loaded through systemd credentials; do not put
secret contents in Nix expressions.
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
or restart the service. Collection starts above `maxBytes`, which is also the
target if `targetBytes` is unset. When both are set, the target must not exceed
the maximum.

The flake also provides a static Linux binary and an OCI archive. Initialize
the persistent data mount and install credentials before serving. The image
runs as UID/GID 65532; arrange matching mount permissions. It does not include
a reverse proxy or provision upload credentials.

### Shared-cache deployment

The module's `publicUrl` is the single shared cache origin for uploads and
downloads. It accepts an HTTP(S) hostname with an optional port, without a path,
trailing slash, credentials, query or fragment. `proxy.enable` derives an Nginx
virtual host from it and requires Narjar's backend to listen on `127.0.0.1` or
`[::1]`. Setting `publicUrl` alone does not enable a proxy or configure Nix.
The managed proxy listens on IPv4; use the Nginx virtual host's `listen` option
to add an IPv6 listener.

The [README](../README.md#shared-cache) has a TLS example. `proxy.tls` selects
`acme` (the default), `existing`, or `off`. For existing certificates:

~~~nix
services.narjar = {
  enable = true;
  publicUrl = "https://cache.example";
  proxy = { enable = true; tls = "existing"; };
};
services.nginx.virtualHosts."cache.example" = {
  sslCertificate = "/run/secrets/cache.crt";
  sslCertificateKey = "/run/secrets/cache.key";
};
~~~

Existing virtual hosts and extra locations are preserved. If another proxy
already serves this origin, leave `proxy.enable` off and route to `listen`
there. NixOS ACME contact, challenge method and firewall access remain under
their native options; evaluation does not request certificates. The module
does not open ports or generate secrets in the Nix store.

For a trusted LAN with explicit plain HTTP:

~~~nix
services.narjar = {
  enable = true;
  publicUrl = "http://cache.example:8080";
  proxy = { enable = true; tls = "off"; };
};
networking.firewall.allowedTCPPorts = [ 8080 ];
~~~

Plain HTTP exposes traffic and bearer tokens to the network. Signature
verification still requires trusted producer keys. Do not use it for secret
uploads or private reads on an untrusted network.

The proxy streams PUT bodies and responses without disk spooling or a second
proxy cache. It forwards Authorization, GET, HEAD, Range and response cache
headers unchanged. The body limit covers `maxEncodedNarBytes` and the 1 MiB
metadata limit.
`proxy.idleTimeoutSeconds` limits gaps between I/O operations, not total request
time. Its default covers a complete upstream fill while narinfo is pending.
`ioTimeoutSeconds` still controls Narjar's socket I/O; the edge has separate
idle and total fill limits.

On consumers, `services.narjar.client` works without enabling the server:

~~~nix
services.narjar.client = {
  enable = true;
  url = "https://cache.example";
  trustedPublicKeys = [ "cache.example:BASE64_PUBLIC_KEY" ];
  mode = "direct";
  substituterPolicy = "append";
  priority = 30;
  fallback = false;
  positiveTtlSeconds = 300;
  negativeTtlSeconds = 1;
};
~~~

`url` defaults to `publicUrl` when both are configured on the same host.
`append` retains existing substituters; `only` explicitly replaces that list.
Lower priorities are tried first. Public keys are appended to Nix's trust list;
they must come from an authenticated operator channel. For read-through
servers, use the upstream producers' keys. The server's `trusted-public-keys`
file is local cache state, not a public HTTP key-distribution endpoint.

`mode = "local-edge"` starts the loopback server, using the same URL and keys
for upstream verification. It requires public reads and `fallback = false`.
An upstream outage becomes a miss at this edge; another configured substituter
can still fail, so select `only` when the edge must be Nix's only cache.
Direct remote substitution does not provide that guarantee. Private direct
clients must separately provision Nix's netrc credential file outside the store.
The existing `edge.configureClient` option remains loopback-only and always
replaces the substituter list; it cannot be combined with `client.enable`.

Set storage limits through the existing `minFreeBytes` and `gc` options. On a
local edge, `edge.leaseSeconds` must cover twice `client.positiveTtlSeconds`
plus 300 seconds. On a shared read-through server, choose a lease that covers
all consumers, including clients not managed by this module. GC retains leased
data even above its target; exhausting admission headroom rejects new fills.

`narjar.service` uses systemd readiness notification. Dependents should use
`Requires=narjar.service` and `After=narjar.service`; remote readiness is
`GET /readyz`. `/metrics` uses Narjar's normal read authentication: public-read
caches expose it publicly, and private caches require a read token. The proxy
does not change this policy. Use an explicit Nginx `/metrics` location with
network restrictions if public reads should not expose metrics. Keep proxy
logs free of Authorization and token values.

For a separately managed proxy, terminate TLS there. Preserve Content-Length and
Authorization, disable PUT request buffering, and align body limits and
timeouts with Narjar. Restrict the direct HTTP listener to loopback or a trusted
network. Socket activation is not supported.
