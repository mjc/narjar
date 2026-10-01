# Crates.io release procedure

Narjar is distributed through Nix today. A crates.io release is an additional
manual distribution channel; CI must never publish a crate. Do not publish a
version without explicit maintainer consent.

## Before choosing a version

- Confirm the exact package name is `narjar` and is available or already owned
  by the intended crates.io account. Record which account or team is authorized
  to publish it; do not assume the GitHub repository owner is the registry
  owner.
- Confirm that account has a verified email address and the required crate
  ownership. Do not put a crates.io token in the repository, Nix store, CI
  configuration, command-line arguments, or logs. CI needs no registry token.
- Review the changes since the previous release and prepare release notes for
  the exact version. Narjar does not currently maintain a separate changelog.
- Select a new SemVer version. A version already published to crates.io cannot
  be overwritten, and a release tag must not be moved to another commit.

## Validate the candidate

1. Update `package.version` in `Cargo.toml` and `Cargo.lock`; the Nix package
   version is read from `Cargo.toml`, so it stays in sync. Prepare release
   notes; commit both changes with the repository's required GPG signature.
2. Confirm the checkout is clean and on the reviewed `main` commit. Verify the
   commit signature with `git verify-commit HEAD`.
3. Run `devenv tasks run check:fmt`, `devenv tasks run check:clippy`,
   `devenv tasks run check:test`, and `devenv tasks run check:doc`. These cover
   the workspace; the doc task runs doctests and denies rustdoc warnings. Then
   run `nix run .#advisory-check` and `nix flake check`.
4. Inspect the package file list with `cargo package --locked --list`. Run
   `bash ci/check-cargo-package.sh`; it packages the crate, checks the archive
   size, builds and tests the extracted source, then installs from that
   extracted archive and exercises the installed binary's `--help` and
   `--version` commands. The flake's `cratePackageCheck` runs this same script
   with a clean Cargo home and vendored dependencies.
5. Inspect `target/package/narjar-<version>.crate` and its file list. The
   repository enforces an 8 MiB ceiling to leave room below crates.io's current
   10 MB archive limit. ([Cargo publishing guide](https://doc.rust-lang.org/cargo/reference/publishing.html))
6. Verify the documented platform/toolchain contract: Rust 1.98 or newer;
   Nix packages for x86_64 Linux and aarch64-darwin; the packaged-archive
   consumer smoke is currently x86_64 Linux only; chunked storage is Linux
   only. Do not claim support for other targets without adding and passing
   their checks.

## Publish only with explicit approval

The following actions are manual and require explicit maintainer consent for
that version. Never add them to a branch-triggered workflow.

1. Create an annotated, signed tag on the reviewed release commit, for example
   `git tag -s vX.Y.Z -m 'narjar vX.Y.Z'`, then verify it with
   `git verify-tag vX.Y.Z`. Push the reviewed commit and tag.
2. After approval, publish the exact reviewed version with
   `cargo publish --locked --registry crates-io`. Naming the registry prevents
   a local `registry.default` setting from redirecting the release. Do not
   print, inspect, or transmit registry credentials as part of the procedure.
3. Confirm Cargo reports publication success and the version appears in the
   crates.io index. Then verify a clean installation with
   `cargo install --locked --registry crates-io --version X.Y.Z narjar`, and
   attach the release notes to the GitHub release for the matching immutable
   tag.

`cargo package --locked` is the pre-publication dry run; it does not upload.
The CI workflow only performs packaging and consumer checks. It has no publish
step or crates.io credential.

## If a published release is broken

Do not try to replace the crate archive or move its tag. Crates.io versions
are immutable. For a broken version, document the impact, yank that version so
new dependency resolution avoids it, prepare a corrected new patch version,
rerun this procedure, and publish the new version only after explicit
maintainer consent. Yanking does not remove the already-published source or
break existing lockfiles.
