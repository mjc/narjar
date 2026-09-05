# NAR semantic model and Git ordering mismatch

This note freezes the model for NARJ-76. The primary references are the
[versioned Nix 2.35 NAR format](https://nix.dev/manual/nix/2.35/protocols/nix-archive/)
and the [Nix archive implementation](https://github.com/NixOS/nix/blob/2.35.2/src/libutil/archive.cc).
NAR begins with `nix-archive-1`; every string is a little-endian u64 byte
length, bytes, then zero padding to eight bytes. Nodes are regular files,
symlinks, or directories. Regular nodes may have an empty `executable` marker
and always have `contents`; symlinks have `target`; directories contain
strictly byte-ascending `entry` records of `name` plus `node`.

The root descriptor is `(kind, payload)`, where kind is `file`, `executable`,
`symlink`, or `directory`; a Git tree alone cannot represent a root file or
symlink, so the descriptor is part of semantic identity. Nix’s parser limits
tag length to 32, name length to 255, target length to 4095, and nesting depth
to 64. Narjar’s future parser must use no larger defensive limits unless a
versioned decision explicitly changes them. Unknown tags/types, duplicate or
out-of-order names, bad lengths/padding, forbidden names, truncation, and
trailing bytes fail closed.

Git maps mode 040000 to directory, 100644 to non-executable regular, 100755
to executable regular, and 120000 to symlink. Mode 160000 is a gitlink and is
rejected: NAR has no submodule node. Git object identity is the object header
(`type length`), body, and selected repository hash algorithm; it is not a NAR
identity. Names must be validated independently because Git tree ordering is
not a NAR serialization oracle.

Git’s [`base_name_compare`](https://github.com/git/git/blob/v2.55.0/tree.c)
compares a directory’s end-of-name as a virtual `/`. Thus the prospective pair
`a.` (file) and `a` (directory) compares as `a.` < `a/` in Git, while NAR’s
byte ordering compares `a` < `a.`. The distinct names can coexist as Git
siblings, and their reversed order proves a serializer must sort canonical NAR
entries itself.

Canonical byte vectors and the negative fixture manifest are in
[`docs/evidence/nar-vectors.json`](evidence/nar-vectors.json). They are
hand-built from the format above and cover root file, root symlink, empty
directory, executable content, unusual byte names, and malformed inputs.

## Field mapping and mismatches

| NAR field/semantic | Git-shaped representation | Result |
| --- | --- | --- |
| root node kind | separate root descriptor; tree for directory | lossless only with the descriptor; a Git tree cannot be a root file or symlink |
| regular `contents` | blob body, mode 100644 or 100755 | lossless for bytes and executable bit |
| symlink `target` | blob body, mode 120000 | lossless as bytes, but checkout behavior is not NAR semantics |
| directory `entry`/`name`/`node` | tree entry `<mode> <name>\\0<oid>` | node mapping is possible; NAR serialization must be regenerated |
| NAR byte name | Git tree name | only names allowed by both formats; NAR forbids empty, `.`, `..`, `/`, and NUL |
| NAR entry order | Git `base_name_compare` order | mismatch: Git appends virtual `/` for directories; sort independently |
| executable marker | Git mode 100755 | preserve as a typed bit, never infer from contents |
| NAR framing/padding | absent from Git object identity | never hash a Git tree as if it were a NAR; canonical re-emission owns framing |

Git tree entries use mode 040000 (tree), 100644 (regular), 100755
(executable), 120000 (symlink), or 160000 (gitlink). Narjar may create only
the first four; 160000 is rejected because NAR has no gitlink/submodule node.
Git raw entry names cannot contain NUL or `/`; filesystem checkout restrictions
are a separate compatibility concern. Git object identity includes its object
header and selected repository hash algorithm, which is distinct from the NAR
byte stream and does not determine NarHash.

The format admits empty file contents and empty directories. Length fields are
u64, so large values are representable by framing, while the implementation
must impose bounded streaming/resource limits. Nix's parser currently limits
tag length to 32, name length to 255, target length to 4095, and nesting depth
to 64; those implementation limits are distinct from the u64 wire type. The
fixture manifest records the malformed forms that must be rejected, including
duplicates, order violations, padding, unknown tags, truncation, trailing
bytes, and forbidden names.

## Current parser behavior and Narjar obligations

| Input property | Nix 2.35.2 behavior | Narjar codec obligation |
| --- | --- | --- |
| non-zero string/content padding | rejected by `readPadding` | reject |
| oversized tag/name/target | rejected at 32/255/4095 bytes | reject at the same limits unless a later versioned decision changes them |
| empty or NUL-containing symlink target | rejected | reject |
| duplicate or descending directory name | rejected by strict ascending comparison | reject |
| depth reaching 64 | rejected | reject |
| bytes after the root node | `parseDump` returns without checking EOF | reject so one object has exactly one canonical byte stream |

The trailing-byte rule is intentionally stricter than the cited Nix parser;
it prevents multiple byte streams from representing the same semantic root.

The versioned source anchors are the
[Nix 2.35 NAR manual](https://nix.dev/manual/nix/2.35/protocols/nix-archive/),
[Nix 2.35.2 `archive.cc`](https://github.com/NixOS/nix/blob/2.35.2/src/libutil/archive.cc),
[Nix 2.35.2 `serialise.cc`](https://github.com/NixOS/nix/blob/2.35.2/src/libutil/serialise.cc),
[Git v2.55.0 `tree.c`](https://github.com/git/git/blob/v2.55.0/tree.c), and
[Git v2.55.0 `tree.h`](https://github.com/git/git/blob/v2.55.0/tree.h).
Git's [data model reference](https://git-scm.com/docs/gitdatamodel/2.55.0)
provides the tree/blob/gitlink type and mode mapping; its object identity is
the header plus body under the repository's selected hash algorithm.
