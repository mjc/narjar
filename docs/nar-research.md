# NAR research tools

These tools are research-only. They read NAR files and cache HTTP traffic; they
do not write to a Narjar data directory.

## Streaming decoder and corpus scan

Build the bounded decoder and scanner with the normal release profile:

```sh
cargo build --release --bin nar-scan
```

`nar-scan` takes one NAR path per line and writes a machine-readable TSV:

```sh
target/release/nar-scan \
  --input-list /path/to/nars.txt \
  --output /path/to/objects.tsv
```

## Canonical streaming encoder

`narjar::nar_encode::Encoder` is a version-1 research-only event sink. It emits
the canonical NAR framing, checks strictly increasing directory names, streams
file chunks directly to its writer, and computes the raw SHA-256 and size in
the same pass. It keeps only the open-node stack and one previous name per open
directory; it does not retain the NAR or file body.

Build and run the RSS harness with the optimized encoder benchmark:

```sh
cargo build --release --bin nar-encode-bench
scripts/nar-encode-memory --output /tmp/narjar-narj77.json
```

The benchmark writes to `io::sink()` and therefore measures encoding work and
memory without disk throughput or compression. The 2026-09-07 run is recorded
at `/tmp/narjar-narj77-20260907-final.json`; its 1 GiB and 20 GiB cases used
1,836 KiB and 1,640 KiB peak RSS respectively.

`nar-reencode` validates byte-for-byte compatibility with an existing Nix NAR
without storing semantic nodes:

```sh
nix-store --dump /nix/store/<path> | target/release/nar-reencode > reencoded.nar
```

The final check used a Nix-produced 120-byte NAR and `cmp` reported identical
input and re-encoded output.

The corpus-wide streaming comparison is recorded at
`/tmp/narjar-narj78-20260907.json`: 7,107 raw NARs totaling 78,503,939,680
bytes produced 7,107 equal outputs and zero mismatches. The comparator uses a
bounded stdin/stdout pipe and emits one result, first-difference offset, input
SHA-256, and command record per NAR.

`O` rows identify exact regular-file payloads by byte offset, length, and
SHA-256, or symlink targets by their raw target bytes. `N` rows contain the
complete raw NAR length and SHA-256 plus structural counts. The decoder hashes
and counts the original stream while emitting bounded file chunks; it does not
materialize file contents.

## Exact reuse report

Run the corpus report after building `nar-scan`:

```sh
scripts/nar-report \
  --manifest benchmarks/corpus-manifest.json \
  --scanner target/release/nar-scan \
  --output /tmp/narjar-exact-dedup \
  --threshold 4096
```

The output contains `objects.tsv`, `report.json`, and `commands.txt`. Candidate
duplicates are reread from their original raw NAR ranges before being counted,
so digest collisions are not treated as reuse. Reports include all corpus
objects, target/machine/family/generation/subset slices, size buckets, and
whole-NAR deduplication. No compression or delta encoding is modeled.

## Real-Nix range and resume trace

Run the recording proxy in front of the deployed cache. The command must use a
store path that is absent from the destination store and the cache's trusted
public key:

```sh
scripts/nix-range-trace \
  --cache-url http://cache.example:5102 \
  --store-path /nix/store/<hash>-<name> \
  --nar-bytes <raw-nar-size> \
  --trusted-public-key '<key-name>:<base64-key>' \
  --trusted-public-key '<second-key-name>:<base64-key>' \
  --output /tmp/narjar-nix-range-trace
```

For each 10%, 50%, and 90% interruption point, plus 32 concurrent fresh
cold-resume copies, the tool logs the interrupted and resumed real `nix copy`
commands plus every forwarded request and response in JSONL. It records 64 KiB
and 1 MiB range workloads at offsets 0, 1, 10%, 50%, 90%, and the final byte.
`summary.json` is the machine-readable result; the trace is the evidence for
whether Nix actually issued `Range` requests after an interruption.

## Decoder memory scaling

Use the FIFO-backed harness to measure the scanner against generated regular
file streams without storing the payloads:

```sh
scripts/nar-memory \
  --scanner target/release/nar-scan \
  --output /tmp/narjar-nar-memory.json
```

The default sizes are 1 MiB, 1 GiB, and 20 GiB. `peak_rss_kib` should remain
bounded by decoder buffers and metadata rather than the declared file size.
