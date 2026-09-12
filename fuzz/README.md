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

The current HTTP/authentication and publication boundaries have separate
targets. They use disposable loopback sockets and temporary directories, so
they do not touch a real cache:

```sh
for target in http_request auth_request narinfo xz_upload; do
  RUSTC="$(rustup which rustc --toolchain nightly)" cargo fuzz run "$target" -- \
    -max_len=1048576 -timeout=5 -rss_limit_mb=256
done
```

`http_request` covers request-line, header, body-length, and Range-bearing
request parsing; `auth_request` adds Basic-auth policy checks; `narinfo`
exercises untrusted narinfo files and signatures; and `xz_upload` exercises
bounded compressed-upload handling. Validation errors are expected; a panic,
hang, or resource-limit breach is not.
