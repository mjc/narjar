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

macOS rejects this backend before initialization because the chunk publication
barrier uses Linux `syncfs`. Use flat storage on macOS.

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

## Supported platforms

Linux CI exercises real Nix transfers with both backends. Apple Silicon CI
builds the package and tests flat storage. Module checks evaluate configuration
and generated startup scripts. See the
[workflow](../.github/workflows/flake.yml) and
[module checks](../nix/module-eval-test.nix).

ZFS is the primary deployment filesystem. `compression=zstd` (`zstd-3`) is
the recommended compression setting; Narjar does not set or check it.
Compression, CoW, sparse extents, and snapshots affect physical space usage.
Narjar's logical byte totals do not measure those effects.

## Unsupported operations

Narjar has no backend migration, legacy-layout fallback, mixed-layout reads,
cross-filesystem publication fallback, online GC, or filesystem management
API. Publication does not require `renameat2`, `O_TMPFILE`, reflinks, NOCOW,
fs-verity, direct I/O, or io_uring.
