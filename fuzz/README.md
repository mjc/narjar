# NAR decoder fuzz target

This is deliberately a separate fuzz crate. It exercises the research decoder
without adding fuzzing dependencies to the Narjar production package.

Install `cargo-fuzz`, then run:

```sh
cd fuzz
RUSTC="$(rustup which rustc --toolchain nightly)" cargo fuzz run nar_decode -- \
  -max_len=1048576 \
  -timeout=5 \
  -rss_limit_mb=256
```

The encoder state-machine target uses the same bounded limits while mutating
directory/file/symlink events:

```sh
RUSTC="$(rustup which rustc --toolchain nightly)" cargo fuzz run nar_encode -- \
  -max_len=65536 \
  -timeout=5 \
  -rss_limit_mb=256
```

The target caps decoder depth, names, entries, file bytes, total bytes, and
work for every input. The command adds libFuzzer's five-second execution-time
and 256 MiB RSS guards. Seed it with malformed lengths, non-zero padding,
duplicate or out-of-order entries, deep nesting, and truncated framing from
the decoder regression tests.
