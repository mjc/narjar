# Dependency advisory checks

From the repository root:

```sh
nix run --no-update-lock-file .#advisory-check
```

In the development environment, use `bash ci/check-cargo-advisories.sh` or
`devenv tasks run check:advisories`.

The check scans the committed `Cargo.lock` with tools pinned by `flake.lock`
and `devenv.lock`. It refreshes the
[RustSec database](https://github.com/RustSec/advisory-db) and queries crates.io
for yanked versions. Either query failing makes the check fail. The database
is cached in Cargo's user cache; the check requires network access.

`--deny warnings` rejects applicable vulnerabilities and warnings for
unmaintained, unsound, or yanked crates. No advisories are ignored. Any
exception must identify the advisory, dependency path, impact, owner, and
removal condition, and appear explicitly in the audit command.

The historical lockfile fixture contains rustls 0.23.44 and must fail for
RUSTSEC-2026-0285, patched in 0.23.45. Its `--no-fetch` scan uses the database
refreshed by the main check. Another fixture verifies that a failed yanked
version lookup cannot pass the check.
