# NARJ-82 repeated subtree measurement

This report uses the retained `narjar-real-nix-v1` corpus and the
candidate-neutral semantic object preimages from NARJ-80. The scanner reads
each raw NAR through Narjar's bounded decoder and retains only one directory's
child metadata at a time. It does not credit descendant file/blob savings to
tree sharing.

- Corpus: 7,080 NARs; all 7,080 manifest artifacts were present.
- Scan time: 164 seconds.
- Raw report: [`trees.tsv`](trees.tsv), one `N` row per NAR plus global `G` and
  unique-tree `T` rows.

## Results

| Measure | Value |
| --- | ---: |
| Tree instances | 269,687 |
| Unique tree objects | 126,179 |
| Repeated instances | 143,508 |
| Embedded logical tree preimage bytes | 102,376,688 |
| Unique logical tree preimage bytes | 67,507,288 |
| Logical bytes saved by sharing | 34,869,400 (34.060%) |
| Separate 4 KiB-object estimate | 1,104,637,952 bytes |
| Shared 4 KiB-object estimate | 516,829,184 bytes |
| Estimated 4 KiB allocation reduction | 587,808,768 bytes |

The 4 KiB figures are an accounting estimate, not a filesystem measurement:
they exclude inode, directory, pack/index, CoW, and filesystem-specific
metadata. Logical tree savings are the portable result. The report's `T` rows
allow occurrence and logical-byte reconciliation without expanding any
descendant blob bytes.

The repeated-subtree characterization test uses two identical child
directories under different names and verifies three tree instances, two
unique trees, and one repeated tree. The existing NAR semantic vectors retain
the executable-mode and Git/NAR ordering counterexamples.
