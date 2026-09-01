#!/usr/bin/env bash
set -euo pipefail

nix flake check -L --no-update-lock-file
