# Release procedure

The `release` workflow is started manually from `main` for an existing signed
tag. It runs the Linux and Apple Silicon checks, prepares the Cargo archive and
static Linux binary, then waits for the repository owner's approval. Pushing a
commit or tag does not publish anything.

## One-time setup

Create a GitHub environment named `release` with these settings:

- Required reviewer: the repository owner, with no other reviewers.
- Allow self-review so the owner can approve a run they started.
- Disable administrator bypass of protection rules.
- Restrict deployment branches to `main`.

The candidate check rejects a missing environment or approval rule. These
settings are repository configuration; adding the workflow does not create them.
GitHub's environment read API does not expose administrator bypass, so disable
that setting in the environment UI.

The first crates.io publication requires an API token. Store a short-lived,
publish-scoped token in the `release` environment secret `CRATES_IO_TOKEN`, not
in a repository-wide secret. After the first publication, revoke that token and
delete the secret. Configure crates.io Trusted Publishing for this repository,
workflow `release.yml`, and environment `release`. Later runs obtain temporary
credentials through OIDC. See the
[crates.io Trusted Publishing documentation](https://crates.io/docs/trusted-publishing).

## Before choosing a version

- Confirm that `narjar` is available or owned by the publishing account.
- Confirm the account's verified email and crate ownership.
- Keep registry tokens out of the repository, Nix store, command arguments,
  and logs. The bootstrap token belongs only in the protected environment.
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
   Separate runners without Nix install the extracted Cargo archive on Linux
   and macOS, inspect its runtime linkage, and run help, version, cache
   initialization, and stats with a minimal environment. Windows CI tests the
   library without application dependencies; the CLI requires Unix. Darwin
   tests use flat storage. Chunked storage is Linux-only.
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

## Start a release

1. Create, verify, and push an annotated signed tag on the reviewed commit:

   ```sh
   git tag -s vX.Y.Z -m 'narjar vX.Y.Z'
   git verify-tag vX.Y.Z
   git push origin main vX.Y.Z
   ```
2. Start the workflow from `main`, passing the tag and release notes:

   ```sh
   gh workflow run release.yml --ref main \
     -f tag=vX.Y.Z -F notes=@release-notes.md
   ```

   Notes should describe the changes and filesystem support boundary. The
   workflow currently accepts stable `vX.Y.Z` tags, not prerelease versions.
3. Inspect the candidate artifacts and passing checks, then approve the
   `publish` job in GitHub. Approval authorizes both crates.io and GitHub
   publication for that candidate.

The workflow verifies GitHub's signature status for the tag and commit, confirms
the commit belongs to the dispatch's `main` history, and checks that the tag
matches `Cargo.toml`. It rechecks the tag after approval. All checks and artifacts
use that exact commit, even if `main` advances.

After approval, it compares Cargo's publish archive with the staged archive,
publishes only the `narjar` package, downloads the registry archive to compare
its bytes, and tests installation of that exact version. It then publishes a
GitHub release containing the `.crate`, static x86_64 Linux binary archive, and
`SHA256SUMS`. The binary archive includes both license files. macOS users install
through Cargo or Nix; no standalone macOS binary is published.
The Linux and macOS runners without Nix then repeat installation from crates.io
using the exact published version. Their failures fail the workflow but cannot
undo publication; extracted-archive installation is checked before approval.

## Retry a partial release

Rerun failed jobs in the same workflow run to retain the staged artifacts. The
workflow skips an existing crates.io version only when its archive matches the
candidate byte-for-byte. It resumes an existing draft GitHub release and verifies
the assets of an already-published release without overwriting them. Registry or
GitHub lookup failures stop the job rather than being treated as missing releases.
Do not change the tag, version, or candidate to resume a partial publication.

`cargo package --locked` does not upload anything.

## If a published release is broken

Document the failure and yank the version if necessary. Yanking prevents new
resolution to it but does not remove its source or invalidate existing
lockfiles. Prepare a new patch version, repeat the checks, and obtain explicit
approval before publishing. Do not replace an archive or move a release tag.
