# NARJ-83 MinCDC baseline

This is the first frozen-corpus measurement for the storage chunking
prototype. It does not authorize or implement a production chunk store, alter
NAR transport bytes, or change the Nix binary-cache protocol.

The primary storage metric is authoritative ZFS dataset `used` after the
candidate store has been fully materialized with the target ZFS compression
property. This captures the candidate representation and ZFS's actual block,
metadata, and inode costs. This prototype writes uncompressed chunk payload
files; there is no separate user-space chunk compressor in this measurement.
If a future candidate adds one, its output must be measured again on ZFS—the
logical sum is not a substitute. Logical sums, apparent file bytes, and the
prototype's per-file allocation walk are diagnostic metrics only; they do not
choose the policy.

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

The bounded materialization check used the first 100 sorted files:

```console
cargo run --release -p narjar-nar-chunking --locked -- \
  --corpus /home/mjc/narjar-corpora/narjar-real-nix-v1 \
  --max-files 100 \
  --store-root /tmp/narj83-store-sample \
  --store-algorithm hash4
```

The pinned experiment parameters are `mincdc = 0.1.0`, an 8 KiB minimum,
24 KiB maximum, and 8 KiB fixed-size control. The recorded `mincdc` source is
the Cargo.lock-selected release. `MinCdcHash4` uses the crate defaults;
`MinCdc4` uses its crate-provided constructor for comparison.

## Results

The physical estimate is unique payload bytes plus manifest bytes. It does
not include filesystem allocation, inode/index overhead, or a serving cache,
so it is not the policy-selection metric. Policy selection requires a fully
materialized store and a ZFS `used` measurement with the intended compression
property.

| Strategy | Logical bytes | Chunks | Unique chunks | Unique bytes | Manifest bytes | Estimated physical bytes | Elapsed | Throughput |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Raw MinCdcHash4 (4–12 KiB) | 78,503,939,680 | 10,079,213 | 5,692,069 | 45,280,622,960 | 483,859,080 | 45,764,482,040 | 138.3 s | 541 MiB/s |
| Raw MinCdc4 (4–12 KiB) | 78,503,939,680 | 14,404,066 | 8,277,548 | 45,344,894,960 | 691,452,024 | 46,036,346,984 | 140.6 s | 533 MiB/s |
| Fixed 8 KiB | 78,503,939,680 | 9,587,246 | 7,335,125 | 60,062,421,072 | 460,244,664 | 60,522,665,736 | 116.1 s | 645 MiB/s |
| Whole-file CAS | 78,503,939,680 | 7,107 | 6,600 | 75,983,475,064 | 341,136 | 75,983,816,200 | 104.9 s | 714 MiB/s |
| Semantic MinCdcHash4 | 78,503,939,680 | 11,007,910 | 6,015,943 | 44,690,362,256 | 536,908,072 | 45,591,458,049 | 197.8 s | 379 MiB/s |
| Semantic MinCdc4 | 78,503,939,680 | 15,196,307 | 8,479,439 | 44,743,177,102 | 737,951,128 | 45,845,315,951 | 319.7 s | 234 MiB/s |
| Hybrid 64 KiB + MinCdcHash4 | 78,503,939,680 | 10,076,365 | 5,690,494 | 45,285,948,702 | 483,697,216 | 45,769,645,918 | 212.1 s | 353 MiB/s |

The fixed raw-Hash4 parameter sweep is:

| Window | Chunks | Unique chunks | Estimated physical bytes | Elapsed | Throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2–8 KiB | 16,259,976 | 8,873,119 | 45,130,575,649 | 225.9 s | 331 MiB/s |
| 4–12 KiB | 10,079,213 | 5,692,069 | 45,764,482,040 | 138.3 s | 541 MiB/s |
| 8–24 KiB | 5,051,561 | 2,949,353 | 46,925,503,905 | 252.6 s | 296 MiB/s |

## Decision

Select raw `MinCdcHash4` with the 8–24 KiB window for the next experiment
slice. The logical sweep alone would choose 2–8 KiB, but the bounded
ZFS-backed stores reversed that result: 2–8 KiB used 113 MiB, 4–12 KiB used
99.0 MiB, and 8–24 KiB used 85.6 MiB for the same 100-file sample. The
larger window avoids enough chunk files and filesystem metadata to win on the
metric that matters here: allocated storage.

The full 8–24 KiB store was then materialized on a temporary `zstd-19` ZFS
dataset. After `zpool sync`, its authoritative dataset usage was
24,088,626,688 bytes (22.434 GiB), with 48,524,743,168 logical bytes and a
2.08× ZFS compression ratio, including chunk files, manifests, and ZFS
metadata. All 14,214 full/90%-resume range checks passed. The deployed
`/var/lib/narjar` dataset used 12,836,595,816 bytes (11.955 GiB) at the same
time, so this full-corpus experiment store was 10.479 GiB larger (1.877×).
That comparison is directional rather than an apples-to-apples replacement
cost: the corpus is 78.5 GB logical while the deployed dataset is 28.3 GB
logical.

The two MinCDC implementations were also materialized in separate temporary
`zstd-19` ZFS datasets using the same 100-file, 232,264,816-byte sample:

| Algorithm | Unique chunks | Apparent bytes | ZFS `used` | ZFS logicalused | ZFS compressratio | Range verification |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `MinCdcHash4` | 14,056 | 223,075,017 | 89,745,920 (85.6 MiB) | 229,654,528 | 2.64× | 824 ms / 295.70 MiB/s |
| `MinCdc4` | 23,156 | 223,757,583 | 98,631,168 (94.1 MiB) | 235,425,280 | 2.49× | 1,002 ms / 243.17 MiB/s |

These are independent dataset `used` readings taken after `zpool sync`, and
include ZFS metadata. Hash4 used about 9% less space in this physical
comparison and was faster for cold range verification. Together with the
full-corpus logical measurements and the full Hash4 materialization above,
this selects `MinCdcHash4`; the `mincdc4` store option remains available to
reproduce the comparison. A pre-sync `zfs list` reading is not valid evidence
for this metric because ZFS usage accounting is asynchronous.

The semantic baseline only improves the estimated physical result by about
165 MiB over the original raw Hash4 window, before filesystem and
semantic-index costs. The fixed 64 KiB whole-small/chunk-large hybrid is also
about 5.2 MiB worse than that original raw Hash4 result, so there is no
measured reason to add either semantic or hybrid policy here.

The semantic rows are deliberately limited evidence: they chunk regular-file
contents independently and retain all other NAR bytes as passthrough. They do
not claim that a semantic manifest can yet reconstruct a NAR byte-for-byte.
That requires the separate semantic codec/reconstruction work tracked by the
blocked dependency. The raw rows do reconstruct exact bytes in the prototype
tests.

No production storage code was changed by this experiment.

## Bounded file-backed store check

The first 100 files contained 232,264,816 logical bytes and 29,357 raw
MinCdcHash4 chunks. The research store wrote 27,909 unique chunk files and
100 manifests:

| Measure | Value |
| --- | ---: |
| Apparent bytes | 222,850,737 |
| Allocated bytes | 92,177,408 |
| Files | 28,009 |
| Directories | 3 |
| Full and 90%-resume ranges verified | 200 |

The selected 8–24 KiB policy was rerun on the same 100-file sample with
range timing enabled. It reconstructed 255,491,335 bytes across those 200
ranges in 877 ms (277.83 MiB/s), with a 10,309,632-byte peak RSS. This is a
cold research-store reconstruction measurement; it includes source and chunk
hash verification and is not an HTTP TTFB or network-serving measurement.

The allocated-byte result is specific to the ZFS dataset and its compression;
it is evidence that file-backed overhead can be measured, not a portable
promise for the eventual storage layout. For this decision, the authoritative
number is the ZFS dataset `used` value after materialization, including ZFS
compression and filesystem metadata. The prototype rejects non-contiguous or
reordered manifests and verifies every chunk hash while serving a range.

The full-corpus physical result above uses post-sync ZFS `used`, not the
prototype's per-file `allocated_bytes` sum. The latter was 23,975,653,888
bytes; ZFS
`used` also includes dataset-level metadata and is therefore the authoritative
on-disk measurement for this experiment.

The store command also reports reconstructed range bytes, range verification
time and throughput, and Linux peak RSS. These measurements are deliberately
kept separate from HTTP serving TTFB: the prototype has no production HTTP
chunk route, so it cannot claim a network-serving result.
