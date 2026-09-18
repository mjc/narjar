# NARJ-83 MinCDC baseline

This is the first frozen-corpus measurement for the storage chunking
prototype. It does not authorize or implement a production chunk store, alter
NAR transport bytes, or change the Nix binary-cache protocol.

## Reproduction

Corpus:

- `/home/mjc/narjar-corpora/narjar-real-nix-v1`
- 7,107 `.nar` files
- 78,503,939,680 logical bytes
- 32,964,764,672 allocated bytes on the source ZFS dataset
- 78,503,939,680 apparent bytes

The source filesystem was ZFS with 128 KiB blocks. The allocated-byte figure
is an environment-specific baseline, not a portable storage estimate.

Commands:

```console
cargo run --release -p narjar-nar-chunking --locked -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1

cargo run --release -p narjar-nar-chunking --locked -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1 \
  --semantic-only
```

The pinned experiment parameters are `mincdc = 0.1.0`, a 4 KiB minimum,
12 KiB maximum, and 8 KiB fixed-size control. The recorded `mincdc` source is
the Cargo.lock-selected release. `MinCdcHash4` uses the crate defaults;
`MinCdc4` uses its crate-provided constructor for comparison.

## Results

The physical estimate is unique payload bytes plus manifest bytes. It does
not include filesystem allocation, inode/index overhead, or a serving cache.

| Strategy | Logical bytes | Chunks | Unique chunks | Unique bytes | Manifest bytes | Estimated physical bytes | Elapsed | Throughput |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Raw MinCdcHash4 | 78,503,939,680 | 10,079,213 | 5,692,069 | 45,280,622,960 | 483,859,080 | 45,764,482,040 | 138.3 s | 541 MiB/s |
| Raw MinCdc4 | 78,503,939,680 | 14,404,066 | 8,277,548 | 45,344,894,960 | 691,452,024 | 46,036,346,984 | 140.6 s | 533 MiB/s |
| Fixed 8 KiB | 78,503,939,680 | 9,587,246 | 7,335,125 | 60,062,421,072 | 460,244,664 | 60,522,665,736 | 116.1 s | 645 MiB/s |
| Whole-file CAS | 78,503,939,680 | 7,107 | 6,600 | 75,983,475,064 | 341,136 | 75,983,816,200 | 104.9 s | 714 MiB/s |
| Semantic MinCdcHash4 | 78,503,939,680 | 11,007,910 | 6,015,943 | 44,690,362,256 | 536,908,072 | 45,591,458,049 | 197.8 s | 379 MiB/s |
| Semantic MinCdc4 | 78,503,939,680 | 15,196,307 | 8,479,439 | 44,743,177,102 | 737,951,128 | 45,845,315,951 | 319.7 s | 234 MiB/s |

## Decision

Select `MinCdcHash4` for the next experiment slice. It is smaller than
`MinCdc4` in both raw and semantic baselines, slightly faster on raw input,
and avoids the severe chunk-count skew visible in `MinCdc4` (average raw
chunk size 5,450 bytes versus 7,788 bytes for Hash4). The semantic baseline
only improves the estimated physical result by about 173 MiB over raw
Hash4, before filesystem and semantic-index costs, so it is not evidence that
semantic storage is worth its added machinery.

The semantic rows are deliberately limited evidence: they chunk regular-file
contents independently and retain all other NAR bytes as passthrough. They do
not claim that a semantic manifest can yet reconstruct a NAR byte-for-byte.
That requires the separate semantic codec/reconstruction work tracked by the
blocked dependency. The raw rows do reconstruct exact bytes in the prototype
tests.

No production storage code was changed by this experiment.
