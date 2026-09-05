# NARJ-75 benchmark constitution

Status: frozen version 1, 2026-09-05. The machine-readable thresholds are in
[`benchmarks/constitution.json`](../benchmarks/constitution.json). Candidate
results must not alter this file; a changed constitution gets a new version,
reason, and review before measurement.

The comparison is the current Narjar binary against a matched raw-NAR cache
using transparent filesystem compression. Both run on Tina, the same ZFS
filesystem, CPU governor, kernel, corpus, proxy, and sample order. HTTP wire
compression is disabled (`compression=none`, `Accept-Encoding: identity`).
Each measured scenario has three warmups and 15 repetitions; cold and warm page
cache runs are labelled separately. Quick runs are smoke tests only.

Every result records the commit, binary and closure identity, host, target,
kernel, filesystem, governor, Nix/Rust/tool versions, exact command, corpus
manifest and category, cache state, repetition count, raw samples, median and
p95. Missing provenance or metric fields is a failed result. Run
`python benchmarks/test_constitution.py` to exercise the boundary evaluator.

The primary metric is median physical-byte savings over the matched baseline:
`100 * (baseline_bytes - candidate_bytes) / baseline_bytes`. Below 25% rejects
the candidate. 25% through below 50% is conditional and chooses the simpler
design only if all hard gates pass. 50% or more is strong evidence, still
subject to all hard gates. Corpus robustness requires improvement in four of
six categories and no category expansion over 5%.

The hard gates cover ingest, full GET, 90%-resume Range TTFB, read
amplification, offline maintenance, active/idle memory, startup, replication,
delta depth/working-set limits, dependency closure, backup, recovery, and
security. Their exact values are frozen in the JSON artifact. The final
decision quotes this constitution verbatim and records rejected alternatives;
thresholds are never tuned to fit observed results.
