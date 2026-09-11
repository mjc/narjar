# Benchmark scripts

The measurement helpers in `scripts/` are standalone Bash programs. They use
the existing release binaries, `/proc`, FIFOs, core Unix tools, and `jq`; no
Python runtime or Cargo tool package is needed.

`tests/measurement-scripts.sh` uses small fake binaries to exercise the three
streaming helpers. It checks encoder RSS output, generated-zero-stream scanner
input, and an equal round trip report without requiring a large corpus.
