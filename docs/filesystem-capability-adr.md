# Filesystem requirements

The operator supplies and mounts DATA. Narjar does not create, tune, snapshot,
scrub, or replicate filesystems. The NixOS module can require the configured
mount before starting the service.

## Required operations

Both backends require:

- directory traversal with no-follow checks;
- private temporary files created exclusively;
- regular-file reads, writes, metadata, and directory enumeration;
- file and directory `fsync`;
- same-filesystem no-replace publication with `linkat`;
- unlink and directory synchronization; and
- an exclusive local `flock` lease.

HTTP delivery uses `sendfile` where available, with a read/write fallback.
Capacity and readiness checks use `fstatvfs`, file checks, and the lease.

## Chunked storage

Chunked storage is Linux-only. New chunks are written and linked in bounded
batches while manifest records remain in staging. Linux `syncfs` completes
the chunk durability step before publication of the manifest. There is no
single-file sync fallback. A chunk directory without a manifest cannot
reconstruct a NAR.

macOS rejects this backend before initialization. Ordinary Apple `fsync`
does not provide the device-cache and ordering guarantees required here;
see [fsync(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
and [fcntl(2)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html).
Flat storage is supported on Apple Silicon macOS, but APFS-specific
power-loss durability is unverified.

## Replacement and repair

Transaction records use `renameat` replacement. Uploaded NARs and narinfos
remain no-replace publications.

Server-generated compressed derivatives can be replaced atomically with
`renameat` after the existing file fails its recorded identity check or,
without a receipt, differs from the newly generated encoded identity. The
replacement is encoded, hashed, flushed, and synced before the rename. The
raw-NAR/codec lock covers repair; source and destination directories are
synced before publication completes. This does not allow replacement of
uploaded objects or narinfos.

## Support boundary

Linux CI exercises real Nix transfers with both backends. Apple Silicon CI
builds the package and tests flat storage. Module evaluation and generated
startup-script checks run without booting a VM. See the
[workflow](../.github/workflows/flake.yml) and
[module checks](../nix/module-eval-test.nix).

There is no dedicated block-device or remount conformance test. XFS, btrfs,
ZFS-specific behavior, overlay and bind-mount variants, quota/inode exhaustion,
and read-only remounts are not established by these checks. NFS, SMB, and FUSE
are unsupported or unverified; they require evidence for link, lock, sync,
and recovery behavior before use as durable DATA.

ZFS is the primary deployment filesystem. `compression=zstd` (`zstd-3`) is
the recommended compression setting; Narjar does not set or check it.
Compression, CoW, sparse extents, and snapshots affect physical space usage.
Narjar's logical byte totals do not measure those effects.

## Unsupported operations

Narjar has no backend migration, legacy-layout fallback, mixed-layout reads,
cross-filesystem publication fallback, online GC, or filesystem management
API. Publication does not require `renameat2`, `O_TMPFILE`, reflinks, NOCOW,
fs-verity, direct I/O, or io_uring.
