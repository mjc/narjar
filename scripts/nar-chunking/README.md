# NAR chunking experiment

This is an isolated NARJ-83 measurement tool. It does not change Narjar's
storage layout or HTTP protocol.

Run it against the frozen corpus with:

```console
cargo run --release -p narjar-nar-chunking -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1
```

The command walks `.nar` files in sorted path order and prints one stable
`key=value` record for each control:

- `raw-mincdc-hash4`: the recommended robust MinCDC implementation;
- `raw-mincdc4`: the faster academic MinCDC implementation;
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
report separately.

Use `--max-files` for a bounded smoke run. The default raw MinCDC parameters
are a fixed 4–12 KiB window and are part of the experiment identity.
