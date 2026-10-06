# Experimental semantic object format

This format is used by the semantic descriptor vectors, not by Narjar's
production storage. It describes semantic object identities and a root
descriptor. The complete NAR retains its own `NarHash` and `NarSize`.

## Hash choice

Internal objects use SHA-256 with domain separation for object kind and format
version. Their hashes are distinct from Git object hashes and the complete
NAR's `NarHash`.

Every multi-byte integer below is unsigned little-endian. Every byte string is
length-delimited by its u64 byte length. Names and symlink targets are raw
bytes, never host strings. The hash of a preimage is the 32-byte SHA-256 digest
of the exact bytes shown.

## Object preimages

The common prefix is the ASCII bytes `narjar-semantic` followed by NUL and the
format version byte `0x01`:

```text
6e61726a61722d73656d616e74696300 01
```

The next byte is the object kind:

```text
0x01  regular file, non-executable
0x02  regular file, executable
0x03  symlink
0x04  directory/tree
```

The remaining fields are:

- regular file or symlink: `u64(length) || bytes`;
- directory: `u64(entry_count)`, then for each entry in ascending raw-byte
  name order: `u64(name_length) || name || u8(child_kind) || child_oid`;
- `child_oid` is exactly 32 bytes and is itself domain-separated.

Tree names cannot be empty, `.`, `..`, or contain NUL or `/`. Duplicate or
non-ascending names fail closed. A child kind is repeated in the tree entry so
decoders do not need to infer mode from an OID or storage record. A tree's
canonical order is the NAR byte-name order, not Git's virtual-slash comparator.

This representation is sufficient to reconstruct every supported root:

| Root | Descriptor kind | Root object |
| --- | --- | --- |
| regular file | `0x01` | regular-file object, with executable bit in object kind |
| symlink | `0x02` | symlink object containing target bytes |
| directory | `0x03` | directory object recursively containing child OIDs/kinds |

The root kind is explicit because a tree object cannot represent a root file or
symlink. Executability is explicit in the regular-object kind and is never
inferred from contents.

## Immutable root descriptor

The descriptor body is:

```text
ASCII "narjar-root" || NUL
u16 format_version          # currently 1
u8  root_kind                # 1=file, 2=symlink, 3=directory
32  root_object_oid
32  authoritative_nar_hash   # raw SHA-256 bytes, not an internal OID
u64 authoritative_nar_size
u16 encoder_version
u16 seek_index_version       # 0 means no derived seek index
```

The checksum is appended as:

```text
SHA256(ASCII "narjar-root-checksum" || NUL || descriptor_body)
```

The complete descriptor is immutable and self-describing: the version and
root kind are not inferred from the file name. A reader must validate the
checksum, supported versions, exact field lengths, root-object existence, and
the stored authoritative hash/size before treating it as a candidate root.
Unknown format, encoder, or index versions fail closed. A seek index and a
materialized raw NAR are derived data; neither participates in the semantic OID
or descriptor checksum except for its declared version.

## Failure and recovery matrix

| Condition | Required result |
| --- | --- |
| Unknown object or descriptor version | Reject; never reinterpret fields |
| Bad checksum, length, kind, or OID | Reject and quarantine/discard the candidate |
| Missing child object | Descriptor remains unpublished; repair by re-ingest or discard |
| Reconstructed bytes disagree with `NarHash`/`NarSize` | Reject the root; do not create narinfo |
| Missing seek index/materialized NAR | Rebuild or serve through another representation; semantic root remains valid |
| Duplicate/out-of-order/invalid name | Reject the tree before publication |
| Mixed object/descriptor versions | Reject unless an explicit compatibility rule names both versions |
| Crash during object or descriptor creation | Temporary data is invisible; startup/reconcile scans and removes/quarantines it |

Any use of this format for publication would need to reconstruct the complete
NAR and verify its hash and size before publishing metadata. The vector tests
do not implement that storage path.

Golden preimage and checksum vectors are in
[`docs/evidence/semantic-descriptor-vectors.txt`](evidence/semantic-descriptor-vectors.txt)
and are checked by [`tests/semantic-descriptor.sh`](../tests/semantic-descriptor.sh).
