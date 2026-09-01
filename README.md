# narjar

Nix is the authoritative development and packaging environment.

## Bootstrap

Install Git and Nix, then run:

\x60\x60\x60sh
nix develop
cargo test --locked
nix flake check -L --no-update-lock-file
\x60\x60\x60

Optional direnv integration uses the tracked `.envrc`:

\x60\x60\x60sh
direnv allow
\x60\x60\x60

The supported systems are `aarch64-darwin` and `x86_64-linux`. Other systems
have no flake outputs by design. `Cargo.toml` and the committed `Cargo.lock`
remain the canonical Rust dependency graph; every flake Cargo invocation uses
`--locked`.

Update inputs deliberately with `nix flake lock --update-input <input>`.
Update Rust dependencies with `cargo update`, review `Cargo.lock`, and commit
the result with a GPG signature. Offline operation is supported after the
inputs and Cargo registry have been realized. If shell evaluation fails,
remove disposable `.direnv/` state and retry `nix develop`; never edit the
lockfiles during ordinary shell entry or checks.
