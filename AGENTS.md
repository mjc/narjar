# Agent instructions

- Use devenv; run noninteractive commands as `devenv shell -- <command>`.
- `.envrc`/direnv is for interactive shells; do not assume it is loaded.
- Use Nix for reproducible builds, packages, apps, and flake checks.
- Keep `Cargo.lock`, `flake.lock`, and `devenv.lock` committed; GPG-sign commits.
