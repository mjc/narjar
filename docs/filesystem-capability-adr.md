# ADR: Portable filesystem capability model

- Status: accepted for the flat and chunked storage implementations
- Scope: DATA filesystem behavior and deployment integration
- Related work: NARJ-43, NARJ-46, NARJ-68, NARJ-69, NARJ-73

## Decision

Narjar requires one operator-provided DATA filesystem with ordinary directory
and regular-file semantics. The filesystem is the source of truth; Narjar does
not discover, create, mount, tune, snapshot, scrub, or replicate a filesystem.
The NixOS module may require the configured mount before starting the service,
but the mount remains administrator-owned.

The portable publication contract for both backends requires:

- directory creation and traversal with no-follow checks;
- private named temporary files created with exclusive creation;
- regular-file reads, writes, metadata, and directory enumeration;
- file and directory `fsync` for the durability boundaries;
- same-filesystem no-replace hard-link publication with `linkat`;
- unlink and directory synchronization for cleanup; and
- an exclusive process lease using local `flock` semantics.

The chunked backend additionally requires bounded creation and traversal of
`.narjar-chunks/` and `.narjar-manifests/`, immutable no-replace chunk and
manifest publication, and enough file/directory synchronization to make a
completed manifest reconstructible after restart. A manifest is authoritative
metadata: a chunk directory without its manifest is not a readable NAR.

Transaction-record replacement uses `renameat` inside the transaction
directory. That is separate from final-object publication. User-uploaded NAR
and narinfo objects remain no-replace publications. Narjar may additionally
use an atomic `renameat` replacement for a server-generated compressed egress
derivative, but only after the existing derivative fails its recorded content
identity check or, when no receipt exists, fails comparison with the newly
materialized server-generated `EncodedIdentity`. The replacement must be fully
encoded, hashed, flushed, and synced. It occurs while holding the raw-NAR/codec
payload lock; the source and destination directories are synced at the same
durability boundaries as other publications. This exception does not apply to
user uploads or narinfo files.

Capacity and readiness diagnostics use `fstatvfs`, regular-file checks, and
the lease. HTTP delivery may use `sendfile` where available, but retains the
portable read/write path as the required behavior.

## Support boundary

The repository's [`nixos-module` VM check](../nix/module-test.nix) exercises the
default `/var/lib/narjar` path on the VM's ext4 root; the
[`module-eval` check](../nix/module-eval-test.nix) covers valid and invalid
`dataDir` declarations. There is no dedicated block-device, tmpfs, or
unmount/remount conformance lane at present. ZFS is the primary
deployment profile, but compression, copy-on-write, sparse extents, snapshots,
and physical space accounting are filesystem observations rather than Narjar
correctness requirements. The chunked backend is intended for a DATA dataset
configured by the operator with `compression=zstd-19`; Narjar does not set or
verify ZFS properties. XFS, btrfs, ZFS-specific behavior, overlay,
bind-mount variants, quota/inode exhaustion, read-only remounts, and Darwin
APFS remain unverified until the corresponding evidence work is complete.

No storage or deployment document should turn an unverified filesystem result
into a support guarantee. The measured filesystem/ZFS profile belongs in the
NARJ-46/NARJ-68 evidence artifacts, not in this capability contract.

## Rejected integrations

The current flat-storage design deliberately does not add:

- automatic backend migration, legacy-layout fallback, or mixed-layout reads;
- libzfs bindings, elevated filesystem privileges, or daemon hooks for
  datasets, snapshots, scrubs, quotas, or replication;
- per-object datasets, Docker-style storage orchestration, or a cross-filesystem
  copy fallback;
- mandatory `renameat2`, `O_TMPFILE`, reflinks, NOCOW, fs-verity, direct I/O,
  or io_uring paths;
- online deletion/GC, resident maintenance workers, or stale GC apply plans;
  or
- unmeasured deduplication, filesystem tuning, or physical-space claims.

These are not hidden extension points. A future integration requires a new
decision backed by portability, crash-recovery, security, and measured
operational evidence.

## Consequences

Keeping the capability model small preserves the current fixed layout,
database-free startup, destination-local staging, immutable publication, and
offline maintenance contract. Operators remain responsible for mounting DATA,
filesystem snapshots/replication, and interpreting physical storage metrics.
Narjar reports logical object accounting and the capacity observations it can
read; it does not pretend those values describe compressed or snapshot-held
physical blocks.
