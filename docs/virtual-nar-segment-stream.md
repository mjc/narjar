# Virtual NAR segment stream

This is the NARJ-94 serving-foundation design. A semantic root is exposed to
consumers as an ordered pull stream of logical NAR bytes. The stream is
representation-neutral: its sources may be semantic objects, raw files,
chunks, or a future packed store, while HTTP remains unaware of that choice.

## Segment model

The stream consists of two segment kinds:

```text
Literal { logical_offset, bytes }
Extent  { logical_offset, length, source: ContentRef }
```

`Literal` contains deterministic NAR framing, names, tags, lengths, and
padding. `Extent` identifies content bytes in an object source; it does not
own or materialize the entire source. Every segment has a checked
`logical_offset` and length. The concatenation invariant is:

```text
first.logical_offset = 0
next.logical_offset = previous.logical_offset + previous.length
last.logical_offset + last.length = authoritative NarSize
```

The generator rejects overflow, gaps, overlap, invalid source ranges, and any
source read that returns an unexpected short result. It emits no final segment
until the source has supplied the requested bytes.

## Traversal and bounded state

The generator uses a pull interface:

```text
next_segment() -> Segment or End or Error
read_extent(segment, output_buffer) -> bytes or Error
```

The caller controls backpressure by requesting the next segment only after it
has consumed the previous one. A bounded output buffer is reused for extents;
there is no whole-NAR buffer. The traversal stack contains at most one frame
per open directory plus the current node. A directory frame owns only that
directory's validated, byte-sorted entry metadata and its iterator. File and
symlink frames hold their fixed framing state and one content reference.

Directory entries are sorted by raw NAR name bytes before emission. The
generator does not use Git's virtual-slash comparator. Names, targets, and
lengths are validated using the NARJ-76 rules before a frame is admitted.

## Worked offset map

`root_symlink_x` from NARJ-78 is 120 bytes. Its complete map is retained in
[`docs/evidence/virtual-nar-segments.tsv`](evidence/virtual-nar-segments.tsv):

| Logical range | Segment | Source |
| --- | --- | --- |
| `[0,24)` | literal | NAR magic and padding |
| `[24,40)` | literal | root-node open marker |
| `[40,56)` | literal | `type` field |
| `[56,72)` | literal | `symlink` value |
| `[72,88)` | literal | `target` field |
| `[88,96)` | literal | target length |
| `[96,97)` | extent | one byte from symlink target object |
| `[97,104)` | literal | target padding |
| `[104,120)` | literal | root-node close marker |

The ranges are contiguous and cover exactly `[0,120)`. A regular file adds a
content extent for its `contents` body; an executable file adds the explicit
`executable` framing before it. A directory adds one literal entry/name
frame per sorted child and recursively traverses that child's object. Empty
roots therefore produce only framing literals and no extents.

## Errors, cancellation, and recovery

Missing or corrupt objects, invalid semantic kinds, failed source reads,
checked-arithmetic overflow, and cancellation terminate the stream with a
typed error. No partial stream is considered a valid reconstructed NAR. The
serving layer may abandon the response; the storage layer can discard or
rebuild derived materializations. The semantic root and descriptor remain
unpublished until a complete stream is hashed and matches authoritative
`NarHash` and `NarSize`.

The stream is not an index. A seek index may store segment checkpoints or
content extents, but it is derived, versioned data and can be regenerated from
the immutable root. Range serving starts traversal from a checkpoint and then
uses the same segment/backpressure contract; it does not add format-specific
HTTP logic.

## Complexity and adapter boundary

For depth `D`, maximum directory fan-out `F`, and `S` emitted segments, live
traversal state is `O(D + F)` metadata plus the bounded I/O buffer. Total work
is `O(S)` framing and source operations, plus the cost of any adapter's object
lookup. Segment count and directory metadata are measured independently; an
adapter that requires whole-root materialization fails this contract.

The raw-file adapter maps one extent to a seek/read range. A semantic adapter
maps content references to object reads. Chunk and packed adapters return the
same extents after reconstruction. None of these adapters may change NAR
framing, name order, root kind, or the authoritative hash/size gate.

The map checker is [`tests/virtual-nar-segments.sh`](../tests/virtual-nar-segments.sh).
