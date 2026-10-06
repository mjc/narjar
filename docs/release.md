# Crates.io release procedure

Publishing is manual and requires explicit maintainer approval for the exact
version. CI packages and tests the crate; it has no publish step or registry
credential.

## Before choosing a version

- Confirm that `narjar` is available or owned by the publishing account.
- Confirm the account's verified email and crate ownership.
- Keep registry tokens out of the repository, Nix store, CI, command arguments,
  and logs.
- Prepare release notes and select an unpublished SemVer version. Published
  versions cannot be overwritten, and release tags must not be moved.

## Validate the candidate

1. Set `package.version` in `Cargo.toml` and update `Cargo.lock`. Nix reads
   the version from `Cargo.toml`. GPG-sign the release commit.
2. Use a clean checkout of the reviewed `main` commit and run
   `git verify-commit HEAD`.
3. Run the repository checks:

   ```sh
   devenv tasks run check:fmt
   devenv tasks run check:clippy
   devenv tasks run check:test
   devenv tasks run check:doc
   nix run -L --no-update-lock-file .#advisory-check
   nix flake check -L --no-update-lock-file
   ```

   Use `devenv shell -- <command>` unless `DEVENV_ROOT` matches this
   checkout. Validation must not change the lockfiles.
4. Inspect `cargo package --locked --list` and run
   `bash ci/check-cargo-package.sh`. This packages the crate, checks its size,
   tests the extracted source with default and minimal features, checks the
   minimal dependency graph, installs from the extracted archive, and runs
   `--help` and `--version`. The flake's `cratePackageCheck` uses vendored
   dependencies and a clean Cargo home.
5. Inspect `target/package/narjar-<version>.crate`. Its compressed size must
   be below the repository's 8 MiB limit, which leaves room below crates.io's
   10 MB limit. See the
   [Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html).
6. Confirm Linux and Apple Silicon CI passed. The package requires Rust 1.98.
   Extracted-archive installation is tested on Linux; Darwin tests use flat
   storage. Chunked storage is Linux-only.
7. Run the real-Nix transfer checks:

   ```sh
   nix run -L --no-update-lock-file .#nix-e2e -- --storage-backend flat
   nix run -L --no-update-lock-file .#nix-e2e -- --storage-backend chunked
   ```

   Linux CI runs these apps. They cover native push, stock Nix uploads,
   independent-store substitution, signatures, corruption rejection, all
   raw/XZ/Zstd directions, interruption, restart, and protected-closure GC.

Module checks inspect configuration and generated startup scripts without
booting a VM. TLS proxy behavior and filesystem-specific power-loss durability
need deployment testing. Preserve the
[filesystem support boundary](filesystem-capability-adr.md#support-boundary)
in release notes. Historical benchmarks are not release requirements.

## Publish only with explicit approval

After approval for this version:

1. Create, verify, and push an annotated signed tag on the reviewed commit:

   ```sh
   git tag -s vX.Y.Z -m 'narjar vX.Y.Z'
   git verify-tag vX.Y.Z
   git push origin main vX.Y.Z
   ```
2. Run `cargo publish --locked --registry crates-io`. Explicit registry
   selection overrides any local default registry.
3. Confirm the version appears in the index, then test
   `cargo install --locked --registry crates-io --version X.Y.Z narjar`.
   Attach release notes to the matching GitHub release.

`cargo package --locked` does not upload anything.

## If a published release is broken

Document the failure and yank the version if necessary. Yanking prevents new
resolution to it but does not remove its source or invalidate existing
lockfiles. Prepare a new patch version, repeat the checks, and obtain explicit
approval before publishing. Do not replace an archive or move a release tag.
