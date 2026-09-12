# Narjar v0.1 operations and resilience contract

Status: design-gate draft for NARJ-11, NARJ-13, and NARJ-14.

## CLI

The binary name is narjar. Secrets are never accepted as positional values or
normal flag values.

~~~text
narjar init
  --data-dir PATH
  [--priority 30]
  [--private-read]

narjar serve
  --data-dir PATH
  [--listen 127.0.0.1:5000]
  [--workers 8]
  [--max-in-flight 64]
  [--max-nar-bytes 17179869184]
  [--min-free-bytes 1073741824]

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

narjar verify
  --data-dir PATH
  [--json]

narjar delete
  --data-dir PATH
  --store-hash HASH
  [--json]

narjar gc
  --data-dir PATH
  [--max-bytes BYTES]
  [--target-bytes BYTES]
  [--max-age-seconds SECONDS]
  [--min-age-seconds SECONDS]
  [--protected-roots PATH]
  [--dry-run | --apply]
  [--json]

narjar list-orphans
  --data-dir PATH
  [--json]

narjar stats
  --url HTTP_URL
  [--netrc-file PATH]
  [--json]

narjar push
  --to STORE_URI
  [--jobs N]
  [--netrc-file PATH]
  [--signing-key-file PATH]
  [--refresh]
  INSTALLABLE...
~~~

init creates the deterministic layout, nix-cache-info, empty token files, and
trusted-public-keys with restrictive modes. It refuses a non-empty incompatible
directory.

token create generates a random 256-bit token, writes only its SHA-256 hash and
label atomically to the scope file, and prints the secret once to stdout.
Callers redirect stdout to a mode-0600 secret store. token revoke removes one
label by atomic file replacement. The secret itself is never in argv, an
environment variable, logs, or the hash file.

push is a client-side convenience command for native Nix copies. It resolves
the requested installables once with `nix path-info --recursive`, partitions
the resulting closure across bounded workers, and invokes native `nix copy`
for each partition. With `--signing-key-file`, it first invokes `nix store sign`
over the complete closure so each native copy can publish trusted narinfo
metadata. `--compression` selects the destination URI's supported NAR
representation (`none` or `xz`) and defaults to `none`. Publication remains
Narjar's existing atomic per-object operation;
push does not parse NARs or implement a second Nix store protocol. The `nix`
executable must be in PATH, and `--netrc-file` is passed to Nix as an HTTP
credential file that must already have restrictive permissions.

delete is offline-only: it refuses while the serve lock is held, removes the
published narinfo after validation and directory sync, and deliberately leaves
the NAR object. list-orphans reports NARs unreferenced by any valid narinfo.
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

Apply removes narinfo first and syncs the cache directory. A referenced NAR is
removed only after its final narinfo is gone, then the nar directory is synced.
Old unreferenced NARs are reclaimed subject to the same minimum-age grace
period. Malformed metadata, missing NARs, symlinked narinfos, and invalid policy
abort the pass before deletion. No online delete endpoint or resident GC worker
is part of this interface.

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
NARJAR_MIN_FREE_BYTES
NARJAR_SHUTDOWN_GRACE_SECONDS
~~~

The compiled defaults bind to loopback, use 8 workers, admit at most 64
in-flight requests, cap one NAR at 16 GiB, and preserve a 1 GiB free-space
reserve. `--data-dir` has no default. A flag or environment value may override
each numeric policy; the shutdown grace defaults to 30 seconds and must be
positive, while zero is valid only for the free-space reserve. Listen addresses
must be numeric IP socket addresses so startup never depends on DNS.

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

Each admitted upload owns at most one temporary file, one descriptor, one hash
state, and one fixed buffer. Reads own one file and one fixed buffer. Memory is
therefore O(workers * buffer-size), independent of NAR size.

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

Publication is globally serialized by one bounded publication worker and the
storage publication mutex. The mutex currently covers admission, temporary-file
creation, the complete request-body stream, validation, durable link, directory
sync, cleanup, and recovery bookkeeping. Reads continue on the read workers,
but a later PUT waits behind an earlier slow PUT. The queue is bounded and
exposes depth and wait metrics; excess requests receive 429 when admission is
full.

This is an intentional v0.1 simplicity tradeoff: a single recovery marker and
one publication order are easy to reason about across crashes. Concurrent
writers still use private temporary files and atomic link-no-replace, so a
retry is identical success or a deterministic conflict. A future narrower
commit section must preserve those durability and recovery invariants; it is
not implied by the current per-object atomicity.

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
| NAR only | invisible as store path | orphan NAR |
| NAR plus narinfo temp | invisible as store path | orphan NAR plus temporary |
| NAR plus published narinfo | readable | valid pair or corruption finding |
| narinfo without NAR | narinfo is quarantinable corruption; normal server returns 404/500 rather than bytes | missing NAR |
| malformed final filename | unreachable by valid route | unknown/invalid file |

Startup never deletes or publishes. It validates the fixed layout and lock, then
serves exact files. Reconciliation is deterministic and operator-triggered.

## Disk-full and I/O failure

Before accepting a NAR, Narjar checks the receiving `DATA/nar/.tmp`
filesystem for declared length plus reserve and at least one free inode. This
is admission guidance, not a guarantee: concurrent writers and other processes
can consume space or inodes.

ENOSPC and EDQUOT return 507 after closing and attempting to remove the temp;
inode exhaustion is also reported as 507 and read-only transitions as 503. EIO,
sync, or directory-sync failure returns 500 and never claims success. Cleanup
failure is logged with request ID and temporary identifier, not a raw arbitrary
path. Metrics expose fixed-cardinality counters for no-space, quota, inode, and
read-only pressure.

Once a narinfo is published, a later NAR read/open failure returns 500 and an
integrity counter. It does not silently return 404 because metadata says the
path should exist.

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

For a consistent portable copy:

1. Stop Narjar and wait for the process to exit.
2. Copy the complete data directory, including `.narjar-clean`,
   `.narjar-recovery`, `lock`, `nar/`, `.tmp/`, `realisations/`, `nix-cache-info`,
   `trusted-public-keys`, and `auth/`.
3. Preserve the directory and file permissions; do not expose the copy while
   it contains credentials.
4. On the destination, run `doctor`, `reconcile --verify-hashes`, and `verify`
   before starting Narjar.
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
concerns. NARJ-32 deliberately rejects access-time retention, online GC, a
resident worker, and an HTTP delete/GC API.

## Observability

Logs are one line per event on stderr using stable key=value fields:

~~~text
level=info event=request_done request_id=... method=PUT route=nar status=201
bytes_in=... bytes_out=... duration_ms=... auth=write token_name=ci
~~~

No field contains Authorization, token bytes, netrc, signature bytes, request
body, arbitrary filesystem path, or query credentials. Store/file hash logging
is configurable and off by default.

GET /healthz is unauthenticated and returns 200 once the HTTP loop is alive.
It says nothing about disk writability or trust configuration.

GET /readyz returns 200 only when the process lock is held, layout and
nix-cache-info are valid, trusted keys are loaded, read access works, and free
space exceeds reserve. It returns 503 with a bounded reason class otherwise.
In private-read mode it requires read authorization; public-read mode leaves it
public.

GET /metrics exposes Prometheus text generated directly from atomic counters,
without a metrics crate. Private-read mode requires read authorization.
Required series:

- `narjar_http_requests_total{method,route,status}` uses fixed method, route,
  and HTTP status-class values (`2xx` through `5xx` plus `other`).
- `narjar_http_bytes_in_total` counts accepted upload body bytes and
  `narjar_http_bytes_out_total` counts served artifact and endpoint bytes.
- `narjar_auth_failures_total{scope}` uses only `read` and `write` scopes.
- `narjar_validation_failures_total{class}` uses only `body`, `nar`, and
  `narinfo` classes.
- `narjar_uploads_in_flight` and `narjar_requests_in_flight` are RAII gauges
  and return to zero after each request completes.
- `narjar_temp_objects` is the current process's temporary-publication count;
  it is updated at create/remove boundaries and does not perform an online
  cache inventory.
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
- narjar_ready 0/1

Labels are fixed enums; no request IDs, paths, token names, or hashes become
metric labels.

## Graceful shutdown

SIGINT/SIGTERM set a shutdown flag, stop admitting new requests, and wait up to
the configured grace period for workers. In-flight uploads may finish within
the grace period; after it, process termination leaves only reconcile-safe
temporaries or already durable immutable files. A second signal exits
immediately. Set systemd `TimeoutStopSec` above the grace period, plus a small
supervisor margin, when the service should be allowed to drain rather than be
externally killed.

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
The NixOS VM check performs state initialization and HTTP requests under those
restrictions, and verifies the credential and state modes.

The separate `filesystem-conformance` NixOS check exercises a real empty
block device formatted as ext4 and a tmpfs DATA mount. It verifies initial
layout creation, restart/reopen across an unmount/remount, and HTTP service.
The existing NixOS module check separately verifies refusal when a declared
DATA mount is unavailable. XFS, btrfs, ZFS, overlay, bind-mount variants,
quota/inode exhaustion, read-only remounts, and Darwin APFS remain unverified
until host-specific lanes provide those fixtures; they must not be advertised
as covered by the portable check.

`GET /healthz` is the liveness endpoint. `GET /readyz` is the readiness
endpoint and requires a read token when private-read mode is enabled. Socket
activation is an explicit v0.1 non-goal because Narjar owns the listener.

For public service, terminate TLS and enforce stream timeouts at a reverse
proxy. This nginx location is also exercised by the NixOS VM check:

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

## Backup and restore

Because published files are immutable, a live backup can exclude every `.tmp`
directory and then verify the copy. Stop the service or snapshot the filesystem after
flushing when a strict point-in-time boundary is required:

~~~sh
backup="/srv/backup/narjar-$(date +%F)"
install -d -m 0700 "$backup"
rsync -a --exclude='/.tmp/' /var/lib/narjar/ "$backup/"
nix run . -- verify --data-dir "$backup"
~~~

Restore into a new mode-0700 directory, restore token hashes and trusted public
keys through the secret manager, verify, and only then point the service at the
restored directory:

~~~sh
restore=/var/lib/narjar-restore
install -d -m 0700 "$restore"
rsync -a --exclude='/.tmp/' "$backup/" "$restore/"
nix run . -- verify --data-dir "$restore"
~~~

The `restored_cache_verifies_before_serving` integration test exercises this
copy, verification, and serving sequence. Missing-NAR findings require reupload
or narinfo quarantine before readiness. A backup contains no producer private
key or plaintext token, but token hashes and trust policy remain
security-sensitive.
