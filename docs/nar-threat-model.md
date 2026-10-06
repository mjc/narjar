# NAR codec limits and validation

This document covers the public `nar` decoder and `nar_encode` encoder. The
cache server verifies uploaded byte identities but does not parse NAR grammar.
Producer signatures do not make archive contents safe to parse.

## Format

NAR starts with `nix-archive-1`. Each string has a little-endian u64 length,
its bytes, and zero padding to an eight-byte boundary. Nodes are regular
files, symlinks, or directories. Regular files have contents and an optional
executable marker; symlinks have a target; directories contain named children
in strictly increasing byte order.

The decoder rejects invalid tags, lengths, padding, names, ordering, symlink
targets, truncation, and bytes after the root. It hashes and counts the original
stream. Callers compare the returned hash and size with any expected identity.
The encoder checks event ordering and writes canonical framing.

See the [NAR format](https://nix.dev/manual/nix/2.35/protocols/nix-archive/)
and [byte fixtures](evidence/nar-vectors.json).

## Current codec defaults

Both codecs use `nar::Limits`:

| Limit | Default |
| --- | ---: |
| Nesting depth | 1,024 |
| Name or symlink target | 1 MiB |
| Entries | 10 million |
| File contents | 64 GiB |
| Total NAR bytes | 128 GiB |
| Work units | 2^34 |

Callers can lower these limits. File contents stream through bounded chunks;
open directories retain traversal and ordering metadata. These defaults are
not a promise that Nix accepts every archive within them. Server upload and
compressed-decoder limits are separate.

The encoder checks byte limits before writes. A failure can leave partial
output; callers must discard it. Input I/O, sink, structural, and limit errors
remain distinct. Neither codec publishes objects or manages disk quotas.

## Tests and fuzzing

`tests/nar_decoder.rs`, `tests/nar_encoder.rs`, and `tests/nar_allocations.rs`
cover malformed input, canonical round trips, limits, typed errors, partial
writes, traversal depth, and buffer reuse. The `nar_decode` and `nar_encode`
fuzz targets use smaller limits to exercise the same boundaries. See the
[fuzzing instructions](../fuzz/README.md).
