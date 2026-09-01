# narjar

Nix is the authoritative development and packaging boundary for narjar.
The flake owns the Rust toolchain, Cargo vendoring, crane artifacts, native
tools, supported targets, checks, and CI commands.

## Bootstrap

Install Git and Nix. From a checkout, run:

```sh
nix develop
cargo test --locked
nix flake check -L --no-update-lock-file
```

The tracked `.envrc` watches both lockfiles and delegates to `use flake`.
Run `direnv allow` once to make direnv and plain `nix develop` select the
same shell. The shell includes Rust 1.85.1, rust-src, rust-analyzer, Cargo,
Nix, direnv, and nix-direnv.

## Supported outputs

| System | Development | Native package | Static package | Runtime checks |
| --- | --- | --- | --- | --- |
| `aarch64-darwin` | yes | yes | no | no |
| `x86_64-linux` | yes | yes | `x86_64-unknown-linux-musl` | yes |

Unsupported `x86_64-darwin` and `aarch64-linux` systems intentionally expose
no outputs. A Darwin cross-build is build evidence only; Linux runtime and
ELF checks run on native Linux CI.

Useful commands are `nix build .#narjar`, `nix build
.#packages.x86_64-linux.narjar-static`, `nix run`, and `nix run
.#provenance`. Provenance reports the lock identity, Nix and Rust versions,
host/target triples, package path, and closure metadata.

## Checks

The format check runs rustfmt in check mode. The source-filter check proves
Cargo files, Rust sources, tests, flake files, direnv configuration, and
README survive filtering while `target` and `.direnv` do not. The lock check
requires both committed lockfiles. Crane's cargo-artifacts layer is built
once and reused by compile/lint, tests, docs, and package checks. The runtime
smoke check executes the packaged binary and the runtime-closure check rejects
compiler, Cargo, analyzer, Nix, and test-tool leakage. Native Linux additionally inspects
the musl ELF for an interpreter and dynamic `NEEDED` entries.

## Updates and recovery

Cargo.toml and committed Cargo.lock are the canonical Rust graph. Update
flake inputs with `nix flake lock --update-input <input>` and Rust
dependencies with `cargo update`; review both diffs and use GPG-signed
commits. Ordinary shell, build, and check commands use `--locked` and do not
update either lockfile.

After an online realization, repeat checks with network access disabled to
verify the store is complete. Binary caches are optional; the crane cache is
configured explicitly in the flake. If direnv or evaluation is broken,
remove only disposable `.direnv/` state and retry `nix develop`. A cold
offline store should fail early with the missing Nix path rather than use
host-installed Rust or native tools.

CI runs the same repository-owned flake checks, then builds and executes the
native Linux package and static ELF checks in a pinned Nix container.
