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

narjar list-orphans
  --data-dir PATH
  [--json]

narjar stats
  --url HTTP_URL
  [--netrc-file PATH]
  [--json]
~~~

init creates the deterministic layout, nix-cache-info, empty token files, and
trusted-public-keys with restrictive modes. It refuses a non-empty incompatible
directory.

token create generates a random 256-bit token, writes only its SHA-256 hash and
label atomically to the scope file, and prints the secret once to stdout.
Callers redirect stdout to a mode-0600 secret store. token revoke removes one
label by atomic file replacement. The secret itself is never in argv, an
environment variable, logs, or the hash file.

delete is offline-only: it refuses while the serve lock is held, removes the
published narinfo after validation and directory sync, and deliberately leaves
the NAR object. list-orphans reports NARs unreferenced by any valid narinfo.
Narjar v0.1 never automatically removes an orphan.

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
~~~

The compiled defaults bind to loopback, use 8 workers, admit at most 64
in-flight requests, cap one NAR at 16 GiB, and preserve a 1 GiB free-space
reserve. `--data-dir` has no default. A flag or environment value may override
each numeric policy; zero is valid only for the free-space reserve. Listen
addresses must be numeric IP socket addresses so startup never depends on DNS.

A TOML configuration file is an explicit v0.1 non-goal. It would add a parser
and duplicate the systemd/container environment boundary. If future option
count makes that trade worthwhile, flags continue to override file values and
environment continues to override only non-secret values.

Example fresh start:

~~~sh
install -d -m 0700 /var/lib/narjar
narjar init --data-dir /var/lib/narjar
narjar token create --data-dir /var/lib/narjar --scope write --name ci > /run/credentials/narjar-ci-token
install -m 0600 producer-public-keys /var/lib/narjar/trusted-public-keys
narjar serve --data-dir /var/lib/narjar --listen 127.0.0.1:5000
~~~

## File ownership and permissions

The service runs as a dedicated unprivileged user.

| Path | Mode | Notes |
| --- | ---: | --- |
| DATA | 0700 | service user owns it |
| DATA/nar and DATA/.tmp | 0700 | no direct web-server access |
| NAR/narinfo/cache-info | 0600 | served only through process |
| auth token files | 0600 | hashes, still security-sensitive |
| trusted-public-keys | 0644 or stricter | public material |
| lock | 0600 | single serving process |

The reverse proxy does not read DATA.

## Request concurrency and timeouts

serve creates a fixed worker set and a bounded queue. max-in-flight limits
requests that have begun processing; excess requests receive 429 when possible
or remain outside Narjar in the proxy accept queue.

Each admitted upload owns at most one temporary file, one descriptor, one hash
state, and one fixed buffer. Reads own one file and one fixed buffer. Memory is
therefore O(workers * buffer-size), independent of NAR size.

Header parsing limits come from tiny_http plus Narjar route checks. Content-
Length is required before upload admission. Narjar does not promise an in-
process socket timeout that tiny_http cannot enforce. The required reverse
proxy sets header, request-body progress, and response timeouts; direct private
use relies on the fixed worker bound. NAR size and minimum free-space checks
happen before and during the stream.

The lock granularity is immutable destination name. Narjar does not create a
global per-object mutex: concurrent writers stream to separate temporary files,
then atomic link-no-replace selects one winner. Losers compare the winner and
return identical success or conflict. This trades duplicate transient I/O for
no lock map, no unbounded key retention, and deterministic crash behavior.

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

Before accepting a NAR, Narjar requires declared Content-Length no greater than
the configured maximum and free space greater than length plus reserve. This is
admission guidance, not a guarantee: concurrent writers and other processes can
consume space.

ENOSPC returns 507 after closing and attempting to remove the temp. EIO,
sync, or directory-sync failure returns 500 and never claims success. Cleanup
failure is logged with request ID and temporary identifier, not a raw arbitrary
path.

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

## Deletion and future GC

v0.1 supports only offline logical deletion of one store hash:

1. Stop serve and acquire the exclusive lock.
2. Parse and validate the named narinfo.
3. Remove narinfo and sync DATA.
4. Leave its NAR untouched.
5. Run list-orphans or verify.

This instantly makes the store path absent while avoiding shared-NAR races.
Clients may retain positive narinfo cache entries until refresh/TTL and then
receive a NAR 200 if they already know its URL; therefore deletion is not a
confidential-erasure feature.

Future offline mark-and-sweep can parse References from existing narinfos and
optional roots/manifests added under a new reserved directory. Existing caches
without publication timestamps are retained conservatively. This needs no
incompatible migration. Access-time retention and online GC remain rejected.

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

- narjar_http_requests_total by method/route/status class
- narjar_http_bytes_in_total and bytes_out_total
- narjar_auth_failures_total by read/write
- narjar_validation_failures_total by stable class
- narjar_uploads_in_flight and requests_in_flight
- narjar_temp_objects observed at startup/reconcile
- narjar_disk_full_total
- narjar_publications_total
- narjar_publication_duration_seconds count/sum/max approximation
- narjar_ready 0/1

Labels are fixed enums; no request IDs, paths, token names, or hashes become
metric labels.

## Graceful shutdown

SIGINT/SIGTERM set a shutdown flag, stop admitting new requests, and wait up to
the configured grace period for workers. In-flight uploads may finish within
the grace period; after it, process termination leaves only reconcile-safe
temporaries or already durable immutable files. A second signal exits
immediately.

Implementation may use signal-hook as the one justified signal dependency.
There is no control socket.

## Deployment

systemd service properties:

~~~ini
User=narjar
Group=narjar
StateDirectory=narjar
ExecStart=/nix/store/.../bin/narjar serve --data-dir /var/lib/narjar
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/narjar
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
CapabilityBoundingSet=
SystemCallArchitectures=native
TimeoutStopSec=30
~~~

Socket activation is an explicit v0.1 non-goal; tiny_http owns the listener.
The NixOS module configures the service, state directory, firewall opt-in,
reverse-proxy example, and secret/public-key credential file paths. It never
places tokens in the Nix store.

The OCI image contains the static binary and an unprivileged numeric user only.
DATA is a volume. TLS and configuration injection remain orchestrator concerns;
the image makes no Docker-specific runtime assumption.

## Backup and restore

Because files are immutable, a live backup copies DATA excluding .tmp, then
runs verify against the snapshot. For a strictly point-in-time coherent backup,
stop serve or snapshot the filesystem after flushing.

Restore into an empty mode-0700 DATA directory, restore token hashes and trusted
public keys through the secret manager, run verify, then start serve. Missing
NAR findings require reupload or narinfo quarantine before readiness.

A backup containing signing public keys and token hashes is security-sensitive
but contains no producer private key or plaintext token.
