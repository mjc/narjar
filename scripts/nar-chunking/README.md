# NAR chunking experiment

This is an isolated NARJ-83 measurement tool. It does not change Narjar's
storage layout or HTTP protocol.

Run it against the frozen corpus with:

```console
cargo run --release -p narjar-nar-chunking -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1
```

Materialize a bounded raw-store sample and verify full plus 90%-resume
ranges with:

```console
cargo run --release -p narjar-nar-chunking -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1 \
  --max-files 100 \
  --store-root /tmp/narj83-store-sample
```

`--store-root` refuses an unbounded run and refuses a non-empty destination.
It uses the selected raw `MinCdcHash4` policy, writes binary manifests and
content-addressed chunks, verifies existing duplicate chunks, and reports
apparent bytes, allocated bytes, and file/directory counts. It is an
experiment store, not Narjar production storage.

Run the fixed raw-Hash4 parameter sweep with:

```console
cargo run --release -p narjar-nar-chunking -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1 \
  --raw-sweep
```

The sweep is deliberately limited to 2–8 KiB, 4–12 KiB, and 8–24 KiB. It is
not an open-ended parameter search.

The command walks `.nar` files in sorted path order and prints one stable
`key=value` record for each control:

- `raw-mincdc-hash4`: the recommended robust MinCDC implementation;
- `raw-mincdc4`: the faster academic MinCDC implementation;
- `hybrid-small-65536`: whole-file CAS for NARs up to 64 KiB, raw
  MinCdcHash4 for larger NARs;
- `fixed-BYTES`: fixed-size chunks, defaulting to 8 KiB;
- `whole-file-cas`: exact whole-file content-addressed storage.

The command also measures `semantic-mincdc-*`: MinCDC is restarted at each
NAR regular-file boundary while directory, symlink, padding, and other NAR
framing bytes remain passthrough bytes. This is a measurement baseline, not a
semantic storage format or a reconstruction implementation.

`logical_bytes` is the input corpus size. `chunked_bytes` is the data covered
by chunk payloads and `passthrough_bytes` is data retained outside the chunk
store. `unique_bytes` is the sum of unique SHA-256-identified payloads.
`manifest_bytes` accounts for an 8-byte per-input-file header plus either
48-byte chunk descriptors (`offset`, `size`, digest) or 40-byte whole-file
descriptors (`size`, digest). `physical_bytes` is their sum; filesystem
allocation, indexes, and inode costs still need to be added to the experiment
report separately. Store runs also report the bytes reconstructed by the full
and 90%-resume checks, their elapsed time, reconstruction throughput, and the
Linux peak resident set (`VmHWM`). Those are cold research-store checks, not
HTTP server latency measurements.

Use `--max-files` for a bounded smoke run. The default raw MinCDC parameters
are the selected fixed 8–24 KiB window and are part of the experiment identity.
