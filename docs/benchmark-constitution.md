# NARJ-75 benchmark constitution

Status: frozen version 4, 2026-09-05. Version 4 adds observed wire compression
to required provenance after the flat control exposed an unmatched external
comparator. Thresholds are unchanged, and no semantic candidate has been
measured. Version 3 restored ticket fields omitted from version 2 and
separated exact-CAS admission from aggressive-delta admission.
The machine-readable thresholds are in
[`benchmarks/constitution.json`](../benchmarks/constitution.json). Candidate
results must not alter this file; a changed constitution gets a new version,
reason, and review before measurement.

The comparison is the current Narjar binary against a matched raw-NAR cache
using transparent filesystem compression. Both run on the same Linux builder,
filesystem, CPU governor, kernel, corpus, proxy, and sample order. HTTP wire
compression is disabled (`compression=none`, `Accept-Encoding: identity`).
Each measured scenario has three warmups and 15 repetitions; cold and warm page
cache runs are labelled separately. Quick runs are smoke tests only.

Every result records the commit, binary and closure identity, host, target,
kernel, filesystem, governor, Nix/Rust/tool versions, exact command, corpus
manifest and category, cache state, observed wire compression, repetition
count, raw samples, median and p95. `provenance.json` carries the run-level
record and `evidence.json` combines it with a schema-valid baseline metric.
Missing provenance or metric fields is a failed result. Run
`tests/evaluate-constitution.sh` to exercise the boundary evaluator.

The primary metric is median physical-byte savings over the matched baseline:
`100 * (baseline_bytes - candidate_bytes) / baseline_bytes`. Below 25% rejects
the candidate. 25% through below 50% is conditional and chooses the simpler
design only if all hard gates pass. 50% or more is strong evidence, still
subject to all hard gates. Corpus robustness requires improvement in four of
six categories and no category expansion over 5%.
Storage-byte samples use allocated filesystem blocks (`st_blocks * 512`), not
logical file lengths, so transparent filesystem compression is included in the
measurement.

The six frozen corpus slices and their exact selectors are in
[`benchmarks/corpus-manifest.json`](../benchmarks/corpus-manifest.json):
many-small-files, shared-subtrees,
duplicate-content, large-contents, symlink-and-executable, and
deep-and-irregular-names. The cardinality-only 10,000-root run is a startup
and RSS control, not a substitute for those six semantic slices.

The hard gates cover ingest, full GET, 90%-resume Range TTFB, read
amplification, offline maintenance, active/idle memory, startup, replication,
delta depth/working-set limits, dependency closure, backup, recovery, and
security. Read amplification is bounded by twice the response bytes plus 1
MiB. Replication is bounded by `max(3 * new_physical_bytes, 0.05 *
live_physical_bytes)`. A gix/delta candidate must improve on exact semantic CAS
by either 10 percentage points or 15% relative. An aggressive-delta candidate
must then add at least 15% beyond the best non-delta candidate, have depth at
most two, and reconstruct no unit over 8 MiB. A hybrid cache is capped at 10%
of logical live bytes and must hit at least 95% of the trace. Compaction may
use one configured segment plus reserve and no second full-cache copy.
Dependencies retain Rust 1.85, have zero advisories, and report binary,
closure, build-time, and transitive growth. Backup must restore into empty
DATA and pass reconcile plus independent Nix verification; security must pass
the auth-capability matrix and secret-free log checks. Their exact values are
frozen in the JSON artifact. The final decision quotes this constitution
verbatim and records rejected alternatives; thresholds are never tuned to fit
observed results.
