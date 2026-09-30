#!/usr/bin/env bash
set -Eeuo pipefail

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck disable=SC1091
source "$script_directory/oci-e2e-podman.sh"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-oci-isolation.XXXXXX")
temp_root="$test_root/private-run"
inherited_root="$test_root/inherited-user-data"
mkdir -p "$temp_root" "$inherited_root"
touch "$inherited_root/keep"

export HOME="$inherited_root/home"
export XDG_CONFIG_HOME="$inherited_root/config"
export XDG_DATA_HOME="$inherited_root/data"
export XDG_RUNTIME_DIR="$inherited_root/runtime"
export TMPDIR="$inherited_root/tmp"
export CONTAINERS_CONF="$inherited_root/containers.conf"
export CONTAINERS_STORAGE_CONF="$inherited_root/storage.conf"
export CONTAINERS_CONF_OVERRIDE="$inherited_root/containers-override.conf"
export CONTAINERS_POLICY="$inherited_root/policy.json"
export CONTAINER_HOST=tcp://127.0.0.1:1234
export CONTAINER_CONNECTION=inherited-connection

fake_bin="$test_root/fake-bin"
mkdir -p "$fake_bin"
podman_log="$test_root/podman.log"
export PODMAN_CALL_LOG="$podman_log"
printf '#!%s\n' "$BASH" >"$fake_bin/podman"
cat >>"$fake_bin/podman" <<'FAKE_PODMAN'
set -eu
{
  printf 'CALL='
  printf '%q ' "$@"
  printf '\nHOME=%s\nXDG_CONFIG_HOME=%s\nXDG_DATA_HOME=%s\nXDG_RUNTIME_DIR=%s\n' \
    "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
  printf 'TMPDIR=%s\nCONTAINERS_CONF=%s\nCONTAINERS_STORAGE_CONF=%s\nCONTAINERS_POLICY=%s\n' \
    "$TMPDIR" "$CONTAINERS_CONF" "$CONTAINERS_STORAGE_CONF" "$CONTAINERS_POLICY"
  printf 'CONTAINERS_CONF_OVERRIDE=%s\nCONTAINER_HOST=%s\nCONTAINER_CONNECTION=%s\n' \
    "${CONTAINERS_CONF_OVERRIDE-<unset>}" "${CONTAINER_HOST-<unset>}" "${CONTAINER_CONNECTION-<unset>}"
} >>"$PODMAN_CALL_LOG"
FAKE_PODMAN
chmod 0700 "$fake_bin/podman"
export PATH="$fake_bin:$PATH"

container_name=narjar-test
readonly_name=narjar-test-readonly
volume=narjar-test-volume
empty_volume=narjar-test-empty-volume
configure_private_podman_roots "$temp_root"
podman info
podman_with_timeout 3 info
cleanup_podman_e2e "$temp_root" "$container_name" "$readonly_name" "$volume" "$empty_volume"

grep -Fqx "CALL=--root $temp_root/podman/storage --runroot $temp_root/podman/run --storage-driver vfs info " "$podman_log"
grep -Fqx "CALL=--root $temp_root/podman/storage --runroot $temp_root/podman/run --storage-driver vfs rm --force narjar-test " "$podman_log"
grep -Fqx "CALL=--root $temp_root/podman/storage --runroot $temp_root/podman/run --storage-driver vfs rm --force narjar-test-readonly " "$podman_log"
grep -Fqx "CALL=--root $temp_root/podman/storage --runroot $temp_root/podman/run --storage-driver vfs volume rm --force narjar-test-volume narjar-test-empty-volume " "$podman_log"
if grep -Fq 'system reset' "$podman_log"; then
  printf 'FAIL: cleanup invoked Podman system reset\n' >&2
  exit 1
fi
[[ $(grep -c '^CALL=' "$podman_log") -eq 5 ]]
if grep '^CALL=' "$podman_log" | grep -Fv 'CALL=--root '; then
  printf 'FAIL: Podman call omitted private storage roots\n' >&2
  exit 1
fi
if grep -Eq 'timeout[[:space:]]+[0-9]+[[:space:]]+podman' "$script_directory/oci-e2e.sh"; then
  printf 'FAIL: OCI script bypasses the isolated timeout wrapper\n' >&2
  exit 1
fi
[[ ! -e "$temp_root" ]]
[[ -e "$inherited_root/keep" ]]
grep -Fqx "HOME=$test_root/private-run/home" "$podman_log"
grep -Fqx "XDG_CONFIG_HOME=$test_root/private-run/podman/config" "$podman_log"
grep -Fqx "XDG_DATA_HOME=$test_root/private-run/podman/data" "$podman_log"
grep -Fqx "XDG_RUNTIME_DIR=$test_root/private-run/podman/runtime" "$podman_log"
grep -Fqx 'CONTAINERS_CONF=/dev/null' "$podman_log"
grep -Fqx 'CONTAINERS_STORAGE_CONF=/dev/null' "$podman_log"
grep -Fqx "CONTAINERS_POLICY=$test_root/private-run/podman/config/containers/policy.json" "$podman_log"
grep -Fqx 'CONTAINERS_CONF_OVERRIDE=<unset>' "$podman_log"
grep -Fqx 'CONTAINER_HOST=<unset>' "$podman_log"
grep -Fqx 'CONTAINER_CONNECTION=<unset>' "$podman_log"

rm -rf -- "$test_root"
printf 'PASS OCI end-to-end Podman commands and cleanup stay inside private roots\n'
