#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

for artifact in flake.nix flake.lock Cargo.toml Cargo.lock .envrc README.md; do
  test -s "$artifact"
done

nix flake check -L --no-update-lock-file
