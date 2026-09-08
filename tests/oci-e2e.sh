#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

log_command() {
  printf '+ ' >&2
  printf '%q ' "$@" >&2
  printf '\n' >&2
}

run() {
  log_command "$@"
  "$@"
}

capture() {
  log_command "$@"
  "$@"
}

expect_failure() {
  local log_file="$temp_root/expected-failure.log"
  log_command "$@"
  if "$@" >"$log_file" 2>&1; then
    cat "$log_file" >&2
    fail "command unexpectedly succeeded"
  fi
  cat "$log_file" >&2
}

image_archive=${NARJAR_OCI_ARCHIVE:?NARJAR_OCI_ARCHIVE must point to an OCI archive}
image=narjar:latest
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-oci-e2e.XXXXXX")
export HOME="$temp_root"
config_home="$temp_root/.config"
run mkdir -p "$config_home/containers"
printf '{"default":[{"type":"insecureAcceptAnything"}]}\n' >"$config_home/containers/policy.json"
export XDG_CONFIG_HOME="$config_home"
export CONTAINERS_POLICY="$config_home/containers/policy.json"
volume=narjar-oci-e2e-${RANDOM}-${RANDOM}
empty_volume=narjar-oci-empty-${RANDOM}-${RANDOM}
container_name=narjar-oci-e2e-${RANDOM}
readonly_name=narjar-oci-readonly-${RANDOM}
container_id=
readonly_id=
server_url=
netrc="$temp_root/netrc"
secret_key_file="$temp_root/cache-secret-key"
public_key_file="$temp_root/cache-public-key"

cleanup() {
  set +e
  [[ -n "$container_id" ]] && podman rm --force "$container_name" >/dev/null 2>&1
  [[ -n "$readonly_id" ]] && podman rm --force "$readonly_name" >/dev/null 2>&1
  podman volume rm --force "$volume" "$empty_volume" >/dev/null 2>&1
  podman system reset --force >/dev/null 2>&1
  rm -rf -- "$temp_root"
}
trap cleanup EXIT

docker_archive="$temp_root/narjar.tar"
run skopeo --policy "$CONTAINERS_POLICY" copy "oci-archive:$image_archive:narjar" "docker-archive:$docker_archive:narjar:latest"
run podman load --input "$docker_archive"
run podman image inspect "$image" >"$temp_root/image.json"
run jq --exit-status --arg user '65532:65532' '
  .[0].Config.User == $user
  and (.[0].Config.Volumes | has("/var/lib/narjar"))
  and (.[0].Config.Entrypoint | length == 1)
' "$temp_root/image.json" >/dev/null

run nix key generate-secret --key-name narjar-oci-e2e >"$secret_key_file"
capture nix key convert-secret-to-public <"$secret_key_file" >"$public_key_file"
public_key=$(<"$public_key_file")

run podman volume create "$volume" >/dev/null
run podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 --mount "type=volume,source=$volume,destination=/var/lib/narjar" \
  "$image" init --data-dir /var/lib/narjar
volume_path=$(capture podman volume inspect --format '{{.Mountpoint}}' "$volume")
run podman unshare cp "$public_key_file" "$volume_path/trusted-public-keys"
run podman unshare chmod 0600 "$volume_path/trusted-public-keys"
run podman unshare test -s "$volume_path/nix-cache-info" || fail "init did not create nix-cache-info"
run podman unshare test -d "$volume_path/nar" || fail "init did not create nar"
run podman unshare test -d "$volume_path/nar/.tmp" || fail "init did not create nar/.tmp"
run podman unshare test -d "$volume_path/.tmp" || fail "init did not create .tmp"
run podman unshare test -d "$volume_path/auth" || fail "init did not create auth"

token=$(capture podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 --mount "type=volume,source=$volume,destination=/var/lib/narjar" \
  "$image" token create --data-dir /var/lib/narjar --scope write --name oci-e2e)
printf 'machine 127.0.0.1\nlogin narjar\npassword %s\n' "$token" >"$netrc"
run chmod 0600 "$netrc"

start_server() {
  local name=$1
  local id
  id=$(capture podman run --detach --name "$name" --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --user 65532:65532 --publish 127.0.0.1::5000 \
    --mount "type=volume,source=$volume,destination=/var/lib/narjar" --tmpfs /tmp "$image")
  if [[ "$name" == "$container_name" ]]; then
    container_id=$id
  else
    readonly_id=$id
  fi

  local port=
  local status=
  for _ in $(seq 1 100); do
    status=$(podman inspect --format '{{.State.Status}}' "$name" 2>/dev/null || true)
    [[ "$status" == exited || "$status" == stopped || "$status" == created ]] && break
    port=$(podman port "$name" 5000/tcp 2>/dev/null | awk -F: 'NF {print $NF; exit}')
    if [[ -n "$port" ]] && curl --fail --silent --show-error --netrc-file "$netrc" \
      "http://127.0.0.1:$port/nix-cache-info" >/dev/null 2>&1; then
      if [[ "$name" == "$container_name" ]]; then
        server_url="http://127.0.0.1:$port"
      fi
      return 0
    fi
    sleep 0.1
  done

  timeout 3 podman start --attach "$name" >&2 || true
  podman inspect --format 'status={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' "$name" >&2 || true
  podman logs "$name" >&2 || true
  fail "$name did not become reachable (state=$status)"
}

start_server "$container_name"

build_path() {
  local nonce=$1
  local expression
  # shellcheck disable=SC2016
  expression='let
    nonce = builtins.getEnv "NARJAR_OCI_NONCE";
  in
  derivation {
    name = "narjar-oci-" + nonce;
    system = builtins.currentSystem;
    builder = "/bin/sh";
    args = [ "-c" "printf %s \"$NARJAR_OCI_NONCE\" > \"$out\"" ];
    NARJAR_OCI_NONCE = nonce;
  }'
  NARJAR_OCI_NONCE="$nonce" capture nix-build --impure --no-out-link --expr "$expression"
}

path=$(build_path persistent)
run nix store sign --key-file "$secret_key_file" "$path"
run nix copy --refresh --option require-sigs false --option netrc-file "$netrc" \
  --to "$server_url?compression=none" "$path"

destination="$temp_root/substituted"
run nix copy --refresh --option require-sigs true --option trusted-public-keys "$public_key" \
  --option netrc-file "$netrc" --from "$server_url?compression=none" \
  --to "local?root=$destination" "$path"
cmp "$path" "$destination${path}" || fail "substituted path differs from pushed content"

run podman rm --force "$container_name"
container_id=
start_server "$container_name"
restart_destination="$temp_root/restarted"
run nix copy --refresh --option require-sigs true --option trusted-public-keys "$public_key" \
  --option netrc-file "$netrc" --from "$server_url?compression=none" \
  --to "local?root=$restart_destination" "$path"
cmp "$path" "$restart_destination${path}" || fail "persistent volume lost artifact after recreate"

run podman volume create "$empty_volume" >/dev/null
expect_failure podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 --mount "type=volume,source=$empty_volume,destination=/var/lib/narjar" \
  --tmpfs /tmp "$image" serve --data-dir /var/lib/narjar --listen 127.0.0.1:5000

wrong_owner="$temp_root/wrong-owner"
run mkdir "$wrong_owner"
run chmod 0700 "$wrong_owner"
expect_failure podman run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --user 65532:65532 --mount "type=bind,source=$wrong_owner,destination=/var/lib/narjar" \
  --tmpfs /tmp "$image" init --data-dir /var/lib/narjar

readonly_id=$(capture podman run --detach --name "$readonly_name" --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --user 65532:65532 --publish 127.0.0.1::5000 \
  --mount "type=volume,source=$volume,destination=/var/lib/narjar,ro" --tmpfs /tmp "$image")
readonly_port=
readonly_ready=0
for _ in $(seq 1 100); do
  status=$(podman inspect --format '{{.State.Status}}' "$readonly_name" 2>/dev/null || true)
  if [[ "$status" == exited || "$status" == stopped ]]; then
    readonly_ready=1
    break
  fi
  readonly_port=$(podman port "$readonly_name" 5000/tcp 2>/dev/null | awk -F: 'NF {print $NF; exit}')
  if [[ -n "$readonly_port" ]] && curl --fail --silent --netrc-file "$netrc" \
    "http://127.0.0.1:$readonly_port/metrics" | grep -Fqx 'narjar_ready 0'; then
    readonly_ready=1
    break
  fi
  sleep 0.1
done
run podman rm --force "$readonly_name" >/dev/null
readonly_id=
(( readonly_ready == 1 )) || fail "read-only DATA did not report an unavailable destination"

printf 'PASS OCI image, uid 65532, read-only root, capability drop, init, persistent volume, real-Nix push/substitute, recreate, empty-data, wrong-owner, and read-only-data verification\n'
