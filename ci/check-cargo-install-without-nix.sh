#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
repository_root=$PWD

if command -v nix >/dev/null 2>&1 || [[ -d /nix/store ]]; then
  printf 'This installation check requires a host without Nix.\n' >&2
  exit 1
fi

pkg-config --modversion sqlite3
version=$(cargo metadata --locked --no-deps --format-version 1 \
  | jq -er '.packages[] | select(.name == "narjar") | .version')
install_options=(--locked --root "$repository_root/target/cargo-install"
  --target-dir "$repository_root/target/cargo-install-build")
if [[ -n "${CARGO_INSTALL_VERSION:-}" ]]; then
  test "$CARGO_INSTALL_VERSION" = "$version"
  cargo install "${install_options[@]}" --registry crates-io --version "=$version" narjar
else
  cargo package --locked --no-verify --package narjar
  tar -xzf "target/package/narjar-$version.crate" -C target/package
  cargo install "${install_options[@]}" --path "target/package/narjar-$version"
fi

binary="$repository_root/target/cargo-install/bin/narjar"
case "$(uname -s)" in
  Linux) ldd "$binary" > target/cargo-install-linkage.txt ;;
  Darwin)
    otool -L "$binary" > target/cargo-install-linkage.txt
    otool -l "$binary" >> target/cargo-install-linkage.txt
    ;;
  *) printf 'Unsupported application platform: %s\n' "$(uname -s)" >&2; exit 1 ;;
esac
cat target/cargo-install-linkage.txt
if grep -Fq /nix/store target/cargo-install-linkage.txt; then
  printf 'Installed binary has a Nix runtime dependency.\n' >&2
  exit 1
fi

run_without_build_environment() {
  env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin "$binary" "$@"
}

test "$(run_without_build_environment --version)" = "narjar $version"
run_without_build_environment --help
run_without_build_environment init --data-dir "$repository_root/target/cargo-install-cache"
test -f target/cargo-install-cache/nix-cache-info
test -d target/cargo-install-cache/nar

url=http://127.0.0.1:17893
env -i HOME="$HOME" PATH=/usr/bin:/bin:/usr/sbin:/sbin "$binary" serve \
  --data-dir "$repository_root/target/cargo-install-cache" --listen 127.0.0.1:17893 \
  > target/cargo-install-server.log 2>&1 &
server_pid=$!
stop_server() {
  kill "$server_pid" 2>/dev/null || true
  wait "$server_pid" || true
}
trap stop_server EXIT
curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 \
  "$url/nix-cache-info" --output target/cargo-install-cache-info.txt
cmp target/cargo-install-cache-info.txt target/cargo-install-cache/nix-cache-info
run_without_build_environment stats --url "$url" > target/cargo-install-stats.txt
grep -q '^narjar_' target/cargo-install-stats.txt
cat target/cargo-install-stats.txt
kill "$server_pid"
wait "$server_pid"
trap - EXIT
