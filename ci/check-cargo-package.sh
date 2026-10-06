#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

package_report_directory=target/package-check
mkdir -p "$package_report_directory"
package_list="$package_report_directory/package-list"

cargo package --locked --allow-dirty --package narjar --list > "$package_list"

required_package_files=(
  Cargo.toml
  Cargo.lock
  LICENSE-APACHE
  LICENSE-MIT
  README.md
  benches/micro.rs
  src/lib.rs
  src/main.rs
  tests/cli.rs
  tests/fixtures/nix-2.31.5-http-v0.1.tsv
  tests/gc_scale.rs
  tests/nar_decoder.rs
  tests/nar_encoder.rs
)

for file in "${required_package_files[@]}"; do
  if ! grep -Fxq "$file" "$package_list"; then
    printf 'required package file is missing: %s\n' "$file" >&2
    exit 1
  fi
done

if grep -Eq '^(benchmarks/results/|\.direnv/|\.devenv/|target/|fuzz/)' "$package_list"; then
  printf 'generated benchmark or local development data entered the Cargo package\n' >&2
  grep -E '^(benchmarks/results/|\.direnv/|\.devenv/|target/|fuzz/)' "$package_list" >&2
  exit 1
fi

crate_version=$(cargo metadata --locked --no-deps --format-version 1 \
  | jq -er '.packages[] | select(.name == "narjar") | .version')
crate_archive="target/package/narjar-${crate_version}.crate"

cargo package --locked --allow-dirty --package narjar

crate_size_bytes=$(wc -c < "$crate_archive")
maximum_crate_size_bytes=$((8 * 1024 * 1024))
if (( crate_size_bytes >= maximum_crate_size_bytes )); then
  printf 'Cargo archive is %s bytes; expected less than %s bytes\n' \
    "$crate_size_bytes" "$maximum_crate_size_bytes" >&2
  exit 1
fi
printf 'Cargo archive: %s bytes compressed\n' "$crate_size_bytes"

cd "target/package/narjar-${crate_version}"

cargo check --locked --all-targets
cargo check --locked --no-default-features --lib
cargo nextest run --locked --no-default-features --lib --test nar_decoder --test nar_encoder --test nar_allocations
library_dependencies=target/library-dependencies.txt
cargo tree --locked --no-default-features --edges normal --prefix none --package narjar > "$library_dependencies"
if grep -Eq '^(clap|httparse|sqlite|sqlite3-sys|ureq|rustix|lzma-rust2|xz4rust|structured-zstd) ' "$library_dependencies"; then
  printf 'library-only consumers must not inherit application dependencies\n' >&2
  exit 1
fi
cargo nextest run --locked --package narjar --all-features

consumer_install_root="$PWD/consumer-install"
cargo install --force --locked --offline --path . --root "$consumer_install_root"

consumer_binary="$consumer_install_root/bin/narjar"
help_output=$("$consumer_binary" --help)
if [[ "$help_output" != *"Usage: narjar <COMMAND>"* ]]; then
  printf 'installed consumer binary returned unexpected --help output:\n%s\n' \
    "$help_output" >&2
  exit 1
fi

version_output=$("$consumer_binary" --version)
expected_version="narjar ${crate_version}"
if [[ "$version_output" != "$expected_version" ]]; then
  printf 'installed consumer binary reported %q; expected %q\n' \
    "$version_output" "$expected_version" >&2
  exit 1
fi
