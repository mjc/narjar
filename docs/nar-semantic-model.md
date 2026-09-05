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
byte ordering compares `a` < `a.`. They cannot coexist as Git siblings, but
the counterexample proves a serializer must sort canonical NAR entries itself.

Canonical byte vectors and the negative fixture manifest are in
[`docs/evidence/nar-vectors.json`](evidence/nar-vectors.json). They are
hand-built from the format above and cover root file, root symlink, empty
directory, executable content, unusual byte names, and malformed inputs.
