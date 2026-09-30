# shellcheck shell=bash
# Shared Podman isolation and cleanup for the OCI end-to-end script.

configure_private_podman_roots() {
  local private_root=$1
  podman_root="$private_root/podman"
  podman_graph_root="$podman_root/storage"
  podman_run_root="$podman_root/run"
  podman_config_home="$podman_root/config"
  podman_data_home="$podman_root/data"
  podman_runtime_dir="$podman_root/runtime"
  podman_tmp_dir="$podman_root/tmp"
  podman_options=(--root "$podman_graph_root" --runroot "$podman_run_root" --storage-driver vfs)

  mkdir -p \
    "$private_root/home" \
    "$podman_graph_root" \
    "$podman_run_root" \
    "$podman_config_home/containers" \
    "$podman_data_home" \
    "$podman_runtime_dir" \
    "$podman_tmp_dir"
  chmod 0700 "$podman_runtime_dir"

  export HOME="$private_root/home"
  export XDG_CONFIG_HOME="$podman_config_home"
  export XDG_DATA_HOME="$podman_data_home"
  export XDG_RUNTIME_DIR="$podman_runtime_dir"
  export TMPDIR="$podman_tmp_dir"
  export CONTAINERS_CONF=/dev/null
  export CONTAINERS_STORAGE_CONF=/dev/null
  export CONTAINERS_POLICY="$podman_config_home/containers/policy.json"
  unset CONTAINERS_CONF_OVERRIDE CONTAINER_HOST CONTAINER_CONNECTION
  printf '{"default":[{"type":"insecureAcceptAnything"}]}\n' >"$CONTAINERS_POLICY"
}

podman() {
  command podman "${podman_options[@]}" "$@"
}

podman_with_timeout() {
  local duration=$1
  shift
  timeout "$duration" podman "${podman_options[@]}" "$@"
}

cleanup_podman_e2e() {
  local private_root=$1
  local container_name=$2
  local readonly_name=$3
  local volume=$4
  local empty_volume=$5

  podman rm --force "$container_name" >/dev/null 2>&1 || true
  podman rm --force "$readonly_name" >/dev/null 2>&1 || true
  podman volume rm --force "$volume" "$empty_volume" >/dev/null 2>&1 || true
  rm -rf -- "$private_root"
}
