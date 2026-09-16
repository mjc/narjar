# HTTP header delimiter scan

Narjar uses one incremental scanner: `memchr::memmem::find` for CRLFCRLF.
It replaces the threshold-based scalar, `memchr`, and `memmem` selection.

The workloads use Nix 2.31.5 request-head sizes recorded in
`docs/evidence/nix-2.31.5-detailed.trace`: 160-byte ordinary GET, 210-byte
NAR HEAD, 213-byte authenticated GET, and a 320-byte authenticated NAR PUT.
The final PUT row passes a 16 KiB buffer because that is narjar's maximum
single `TcpStream::read` destination; it models a head coalesced with a body
prefix, not a claimed network-fragment distribution.

| Recorded Nix request shape | Scalar median | `memmem` median | Improvement |
| --- | ---: | ---: | ---: |
| GET (160 B head) | 129.0 ns | 55.8 ns | 2.31x |
| HEAD NAR (210 B head) | 126.2 ns | 48.5 ns | 2.60x |
| authenticated GET (213 B head) | 132.2 ns | 45.8 ns | 2.89x |
| authenticated NAR PUT (320 B head, 16 KiB read cap) | 226.5 ns | 47.7 ns | 4.75x |

The byte-by-byte and delimiter-split inputs remain in the benchmark's
invariant check. They establish that incremental scanning retains the first
delimiter across read boundaries; they are deliberately not performance
workloads.

Five serial release samples are recorded in `raw.txt`. Each row has 100,000
timed iterations after 10 warmups. Command:
`devenv shell -- cargo bench --locked --bench micro`.
