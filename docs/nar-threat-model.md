# Semantic NAR threat model

This is the Phase A boundary for the decoder and encoder prototypes. A valid
producer signature authenticates metadata; it does not make the producer or
its key holder non-malicious. The codec therefore rejects malformed and
non-canonical input before it can become a reader-visible semantic root.

| Input or actor | Resource/correctness impact | Enforcing boundary | Evidence | Recovery | Residual risk |
| --- | --- | --- | --- | --- | --- |
| Authenticated malicious writer | Deep nesting and stack/heap growth | `Limits::max_depth`; iterative encoder/decoder node stacks | decoder limit tests; bounded encoder fuzz target | Reject the object before publication | Limits must remain aligned with deployment budgets |
| Authenticated malicious writer | Huge names or symlink targets | `max_name_bytes`, `max_symlink_target_bytes`; raw-byte validation | decoder and encoder boundary tests | Reject the object and retain no root | A high limit can still be operationally expensive |
| Authenticated malicious writer | Entry/inode fan-out | `max_entries` and `max_work` | decoder limit tests; encoder event-work limit | Abort the event stream before object creation | Semantic object/inode quotas are later admission work |
| Authenticated malicious writer | File/NAR memory or disk exhaustion | `max_file_bytes`, `max_total_bytes`; file bodies stream in chunks | 20 GiB RSS harness; decoder/encoder size checks | Fail closed and discard incomplete output | Publication/storage quotas remain separate |
| Corrupted or truncated NAR | Wrong hash, size, or reconstructed bytes | Exact framing, padding, EOF, hash, and size validation | decoder negative tests; corpus byte round trips | Do not expose a root; retry transport if applicable | Transport-level corruption still needs retry policy |
| Non-canonical producer | Hash identity drift from directory order or names | Strict ordering, forbidden-name, executable-marker, and NUL checks | NARJ-78 corpus equality and negative tests | Reject rather than normalize | New grammar versions require a new contract version |
| Faulting output/storage sink | Partial semantic publication | `Write::write_all` plus typed `EncodeError::Io`; caller must discard failed output | faulting/short-write tests | Remove or quarantine the failed temporary | Publication recovery belongs to storage boundaries |
| Unauthenticated reader | Range or reconstruction CPU amplification | No reconstruction or serving integration in this prototype; raw codec work is bounded | explicit non-goal; future range limits required | Serving layer must reject over-budget work | Serving design must enforce separate read budgets |
| Compromised producer key | Malicious but correctly signed archives | Same parser/codec limits and canonical checks; signature is not a trust bypass | fuzz and limit targets | Reject malformed objects and rotate/revoke keys operationally | Key rotation and operator response are outside this codec |

## Frozen Phase A limits

`nar::Limits::default()` is the secure prototype default: depth 1,024;
names/targets 1 MiB; 10 million entries; 64 GiB per file; 128 GiB total raw
NAR bytes; and 2^34 work units. Fuzz targets use substantially smaller
limits to make boundary transitions frequent and deterministic.

The encoder uses the same limit structure as the decoder. It checks limits
before writing the bytes that would exceed them, so a rejected event cannot
silently extend the output past the configured raw-size budget.

## Fuzzing boundary

`nar_decode` mutates arbitrary raw bytes under bounded decoder limits.
`nar_encode` mutates event transitions, names, targets, file sizes, chunks,
and close events under bounded encoder limits. Neither target treats a crash
or timeout as proof of safety; retained failures become minimized regression
fixtures. Descriptor, seek-index, pack/object, delta, and range-amplification
targets remain future work as those surfaces are introduced.
