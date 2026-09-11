# Gitoxide bounded semantic-object I/O probe

This is the NARJ-93 experiment against the exact graph audited by NARJ-86:
`gix-odb 0.84.0`, `gix-pack 0.74.2`, `gix-object 0.64.1`, `gix-hash 0.26.2`,
and `gix-features 0.49.1`. The disposable Rust probe is kept outside the
repository at `/tmp/narjar-gix-probe`; it uses `gix_odb::loose::Store`
directly and excludes the high-level `gix` facade.

## Method

The probe uses a generated reader that emits a constant byte without creating
an input buffer proportional to the declared size. For every size it:

1. streams a loose blob into `Store::write_stream`;
2. independently computes the Git object ID with
   `gix_object::compute_stream_hash`;
3. compares the IDs; and
4. optionally reads the object with `try_find`, which supplies a caller-owned
   `Vec<u8>`.

Read concurrency is controlled by `GIX_PROBE_STREAM_READERS`. Peak memory was
sampled from `/proc/<pid>/status` `VmHWM` every 5 ms while the release probe
ran. The large write was sampled the same way. These are process HWM samples,
not allocator-instrumentation results, so they do not claim a complete
allocator profile.

The reproducible probe commands were:

```sh
nix develop /home/mjc/projects/narjar -c env RUSTC_WRAPPER= cargo build --release
GIX_PROBE_LARGE_SIZE=1073741824 target/release/narjar-gix-probe
GIX_PROBE_STREAM_READERS=32 target/release/narjar-gix-probe
```

The HWM wrapper launched the same binary, polled `/proc/$pid/status`, and
reported the maximum `VmHWM`; it did not retain the generated 1 GiB temporary
object after the probe exited.

## Results

| Operation | Input/object size | Result | Peak `VmHWM` |
| --- | ---: | --- | ---: |
| loose write + read, one reader | 1 B | pass; independent OID matched | not retained separately |
| loose write + read, one reader | 64 KiB | pass; independent OID matched | not retained separately |
| loose write + read, one reader | 8 MiB | pass; independent OID matched | not retained separately |
| loose streaming write, no read-back | 1 GiB | pass; independent OID matched | 10,708 KiB |
| 32 concurrent loose reads | 8 MiB each | pass; independent OIDs matched | 261,640 KiB |

The 32-reader result is consistent with each `try_find` owning a complete
8 MiB output buffer. It is not an O(1)-with-payload read path: the result is
about 256 MiB before allocator/page-accounting differences. The write path is
bounded for the generated 1 GiB stream, but that does not make whole-file
reads viable. NARJ-75's frozen per-operation working-set budget is 16 MiB;
an 8 MiB object is below that individual limit, but a whole-file object can
exceed it as soon as the object size crosses the budget.

## Boundary behavior

- A 5-byte loose object read with `alloc_limit_bytes = 4` is rejected.
- A declared 6-byte stream that supplies 5 bytes is rejected.
- A reader that supplies 6 bytes while the caller declares 5 bytes is accepted
  and leaves one byte unread. The caller must enforce EOF if exact stream
  length is required; gix's hash helper alone does not do that.
- Four concurrent reads of a small object and 1/8/32 concurrent reads of the
  8 MiB object completed successfully with cache-free direct loose-store
  operations. The 32-reader 8 MiB HWM is the retained concurrency measurement.
- SHA-1 and SHA-256 feature combinations compile in the same probe graph.

## Decision

Whole-file gix objects are rejected from Narjar's hot read path. A future gix
prototype would need bounded chunks, an explicit EOF/length wrapper, a strict
process concurrency budget, caller-side expected-OID validation, and separate
tests for packed/delta objects. The current evidence does not justify adding
gix to Narjar or treating its per-object allocation limit as a process-wide
memory limit. The result is therefore **no gix for whole-file hot I/O**;
bounded chunks remain a separately authorized prototype, not an accepted
configuration.

Raw probe outputs and the exact commands are summarized in
[`docs/evidence/gix-bounded-io.tsv`](evidence/gix-bounded-io.tsv). The existing
[`docs/gix-audit.md`](gix-audit.md) records the broader API and durability
decision.
