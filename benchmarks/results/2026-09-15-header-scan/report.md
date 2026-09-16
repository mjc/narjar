# Incremental HTTP header scan

The parser-only benchmark compares the previous full-prefix CRLFCRLF scan with
an incremental scan that retains the final three bytes from the previous
chunk. It uses a 4096-byte non-terminator prefix followed by the terminator
and tests 1-byte, 4-byte, 64-byte, and 1 KiB input chunks.

The median of five release runs was:

| Chunk | Full-prefix rescan | Incremental scan | Improvement |
| --- | ---: | ---: | ---: |
| 1 B | 4,322,580 ns/op | 8,285 ns/op | 522x |
| 4 B | 1,077,785 ns/op | 2,346 ns/op | 459x |
| 64 B | 54,570 ns/op | 2,137 ns/op | 26x |
| 1 KiB | 5,854 ns/op | 985 ns/op | 6x |

The production request reader now uses the incremental scan. The invariant
check places CRLFCRLF after every prefix length from zero through 4096 and
also checks an input with no terminator, so split terminators cannot be missed.

Provenance: Rust 1.98.1, Cargo 1.98.1, five invocations of the command in
`raw.txt`, 100 timed iterations per row after the harness warmup.
