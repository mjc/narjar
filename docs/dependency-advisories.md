# Dependency advisory checks

Run the advisory gate from the repository root:

```sh
nix run --no-update-lock-file .#advisory-check
```

Inside the project development environment, the same check is available as
`bash ci/check-cargo-advisories.sh` or the `check:advisories` task.

The executable and Cargo are provided by the Nixpkgs revisions in `flake.lock`
and `devenv.lock`; no CI step downloads an unpinned tool. The audit scans the
committed `Cargo.lock` without resolving or changing dependencies. Cargo is
also required for the registry query used to check yanked releases; inability
to update the crates.io index fails the gate instead of silently skipping that
check.

Each run refreshes the RustSec advisory database from
`https://github.com/RustSec/advisory-db`. CI therefore evaluates current
advisories rather than a checked-in snapshot. The cloned database is cached in
Cargo's user cache for local runs. Network access is required for a fresh or
stale advisory database and for the crates.io index query. The regression
fixture runs with `--no-fetch` only after the main audit refreshed the database,
so both scans use the same advisory data.

The gate uses `--deny warnings`, so applicable vulnerabilities and warnings for
unmaintained, unsound, or yanked crates fail CI. There are no ignored advisories
or exceptions. If an exception becomes unavoidable, it must name one advisory
and document the affected dependency path, impact, responsible owner, and a
specific removal condition. The exception must be added explicitly to the audit
command; blanket ignores are not permitted.

The checked-in historical lockfile fixture contains rustls 0.23.44. It must
continue to fail specifically for RUSTSEC-2026-0285, whose patched release is
rustls 0.23.45.
