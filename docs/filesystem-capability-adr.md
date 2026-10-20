# Filesystem requirements

The operator supplies and mounts DATA. Narjar does not create, tune, snapshot,
scrub, or replicate filesystems. The NixOS module can require the configured
mount before starting the service.

## Required operations

Both backends require:

- directory traversal with no-follow checks;
- private temporary files created exclusively;
- regular-file reads, writes, metadata, and directory enumeration;
- file and directory synchronization;
- same-filesystem no-replace hard-link publication;
- unlink and directory synchronization; and
- an exclusive local process lease.

Unix uses `fsync`, `linkat`, and a directory `flock` lease. Windows flat storage
uses local NTFS, writable directory handles for `FlushFileBuffers`, and a locked
lease file that cannot be replaced while held. Only initialization may create
that lease file; opening an existing cache does not create missing layout files.

Windows operations resolve children relative to retained directory handles and
reject reparse points, alternate data streams, and ambiguous DOS names. Private
DACLs are installed when files and directories are created. They are not replaced
with Unix-mode approximations.

Online GC requires a private local Unix-domain socket or Windows named pipe.
The pipe name includes the account SID and opened DATA identity; remote pipe
clients are rejected.

HTTP delivery uses `sendfile` where available, with a read/write fallback.
Capacity and readiness probes use `fstatvfs` on Unix or Windows volume APIs.
Windows reports quota-available bytes and read-only state, without inventing an
inode count. Startup validates the fixed layout and acquires the exclusive lease.

## Chunked storage

Chunked storage is Linux-only. New chunks are written and linked in bounded
batches while manifest records remain in staging. Linux `syncfs` completes
the chunk durability step before publication of the manifest. There is no
single-file sync fallback. A chunk directory without a manifest cannot
reconstruct a NAR.

macOS and Windows reject this backend before initialization because the chunk
publication barrier uses Linux `syncfs`. Use flat storage on those platforms.

## Replacement and repair

Transaction records use atomic same-volume replacement. Uploaded NARs and narinfos
remain no-replace publications.

Server-generated compressed derivatives can be replaced atomically with
rename after the existing file fails its recorded identity check or,
without a receipt, differs from the newly generated encoded identity. The
replacement is encoded, hashed, flushed, and synced before the rename. The
raw-NAR/codec lock covers repair; source and destination directories are
synced before publication completes. This does not allow replacement of
uploaded objects or narinfos.

## Unsupported operations

Narjar has no backend migration, legacy-layout fallback, mixed-layout reads,
cross-filesystem publication fallback, or filesystem management
API. Publication does not require `renameat2`, `O_TMPFILE`, reflinks, NOCOW,
fs-verity, direct I/O, or io_uring.
