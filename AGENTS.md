# Agent instructions

- Use devenv; run noninteractive commands as `devenv shell -- <command>`, unless `DEVENV_ROOT` is set to the project root, in which case run commands directly.
- Use Nix for reproducible builds, packages, apps, and flake checks.
- Keep `Cargo.lock`, `flake.lock`, and `devenv.lock` committed; GPG-sign commits.
