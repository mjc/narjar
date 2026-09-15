# Repository instructions

## Development environment

- Use devenv as the project development environment.
- Interactive shells may load devenv through direnv and the repository's `.envrc`.
- Automation and agent command runners must not assume direnv is loaded. Run
  tool-dependent commands explicitly as `devenv shell -- <command>`.
- Do not use `nix develop`; Nix remains the interface for reproducible builds,
  packages, apps, and flake checks.

## Reproducibility

- Keep `Cargo.lock`, `flake.lock`, and `devenv.lock` committed.
- Commits must be GPG-signed.
