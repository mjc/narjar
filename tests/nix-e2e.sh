#!/usr/bin/env bash
set -euo pipefail

trace() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
}

run() {
  trace "$@" >&2
  "$@"
}

nix_cli() {
  run nix --extra-experimental-features nix-command "$@"
}

cache_curl() {
  run curl --fail --silent --show-error --netrc-file "$netrc" "$@"
}

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

scenario() {
  printf '\nSCENARIO %s\n' "$1"
}

expect_file() {
  [[ -f "$1" ]] || fail "expected file: $1"
}

expect_missing() {
  [[ ! -e "$1" ]] || fail "expected no published path: $1"
}

server_pid=
server_url=
stop_server() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid"
    wait "$server_pid" || true
  fi
  server_pid=
}

crash_server() {
  kill -KILL "$server_pid"
  wait "$server_pid" || true
  server_pid=
}

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-nix-e2e.XXXXXX")
temp_root=$(cd "$temp_root" && pwd -P)
cleanup() {
  stop_server
  rm -rf -- "$temp_root"
}
trap cleanup EXIT

data_dir="$temp_root/server"
server_stdout="$temp_root/narjar.stdout"
server_log="$temp_root/narjar.log"
netrc="$temp_root/netrc"
secret_key="$temp_root/cache-secret-key"
public_key="$temp_root/cache-public-key"
wrong_secret_key="$temp_root/wrong-secret-key"
wrong_public_key="$temp_root/wrong-public-key"

start_server() {
  : > "$server_stdout"
  run narjar serve --data-dir "$data_dir" --listen 127.0.0.1:0 \
    >"$server_stdout" 2>>"$server_log" &
  server_pid=$!

  local attempts=0
  local startup_line=
  while (( attempts < 500 )); do
    if [[ -s "$server_stdout" ]]; then
      IFS= read -r startup_line < "$server_stdout"
      break
    fi
    kill -0 "$server_pid" 2>/dev/null || {
      cat "$server_log" >&2
      fail "narjar exited before reporting its address"
    }
    sleep 0.01
    ((attempts += 1))
  done
  [[ "$startup_line" == listening\ http://127.0.0.1:* ]] || {
    cat "$server_log" >&2
    fail "unexpected startup line: $startup_line"
  }
  server_url=${startup_line#listening }
  server_url=${server_url%% *}
  printf 'SERVER %s\n' "$server_url"
}

build_path() {
  local build_nonce="$2-$1"
  # The single-quoted expression is expanded by Nix, not Bash.
  # shellcheck disable=SC2016
  NARJAR_E2E_BUILD_NONCE="$build_nonce" run nix-build --impure --no-out-link --expr 'let
      nonce = builtins.getEnv "NARJAR_E2E_BUILD_NONCE";
    in
    derivation {
      name = "narjar-e2e-" + nonce;
      system = builtins.currentSystem;
      builder = "/bin/sh";
      args = [ "-c" "printf %s \"$NARJAR_E2E_NONCE\" > \"$out\"" ];
      NARJAR_E2E_NONCE = nonce;
    }'
}

sign_path() {
  nix_cli store sign --key-file "$secret_key" "$1"
}

cache_copy_to() {
  nix_cli copy --refresh \
    --option netrc-file "$netrc" \
    --to "$server_url?compression=none" \
    "$@"
}

substitute() {
  local destination_root=$1
  local trusted_key=$2
  local store_path=$3
  nix_cli copy --refresh \
    --option netrc-file "$netrc" \
    --option require-sigs true \
    --option trusted-public-keys "$trusted_key" \
    --from "$server_url?compression=none" \
    --to "local?root=$destination_root" \
    "$store_path"
}

nar_url_for() {
  local store_path=$1
  local store_name=${store_path#/nix/store/}
  local store_hash=${store_name%%-*}
  cache_curl "$server_url/$store_hash.narinfo" |
    grep '^URL: ' |
    cut -d ' ' -f 2
}

http_status() {
  run curl --silent --output /dev/null --write-out '%{http_code}' \
    --netrc-file "$netrc" "$1"
}

wait_for_temp() {
  local upload_pid=$1
  local attempts=0
  while (( attempts < 500 )); do
    if find "$data_dir/.tmp" -type f -print -quit | grep -q .; then
      return
    fi
    kill -0 "$upload_pid" 2>/dev/null ||
      fail "upload exited before creating a temporary file"
    sleep 0.01
    ((attempts += 1))
  done
  fail "upload did not create a temporary file"
}

printf 'NIX_VERSION '
run nix --version
printf 'TEMP_ROOT %s\n' "$temp_root"
nonce=$(date +%Y%m%d%H%M%S)-$$

run nix key generate-secret --key-name narjar-e2e > "$secret_key"
run nix key convert-secret-to-public < "$secret_key" > "$public_key"
run nix key generate-secret --key-name wrong-e2e > "$wrong_secret_key"
run nix key convert-secret-to-public < "$wrong_secret_key" > "$wrong_public_key"
trusted_key=$(<"$public_key")
wrong_key=$(<"$wrong_public_key")

run mkdir -p "$data_dir"
token=$(run narjar token create --data-dir "$data_dir" --scope write --name nix-e2e)
run cp "$public_key" "$data_dir/trusted-public-keys"
umask 077
printf 'machine 127.0.0.1\nlogin narjar\npassword %s\n' "$token" > "$netrc"
run chmod 0600 "$netrc"

start_server

scenario 'isolated destination, native push, substitution, content'
primary_path=$(build_path primary "$nonce")
sign_path "$primary_path"
seed_root="$temp_root/seed-store"
nix_cli copy --option require-sigs false --to "local?root=$seed_root" "$primary_path"
expect_file "$seed_root$primary_path"
nix_cli store delete --store "local?root=$seed_root" "$primary_path"
expect_missing "$seed_root$primary_path"
cache_copy_to "$primary_path"

trusted_root="$temp_root/trusted-store"
substitute "$trusted_root" "$trusted_key" "$primary_path"
expect_file "$trusted_root$primary_path"
run cmp "$primary_path" "$trusted_root$primary_path"
nix_cli store verify --store "local?root=$trusted_root" \
  --sigs-needed 1 \
  --option trusted-public-keys "$trusted_key" \
  "$primary_path"

scenario 'untrusted signing key is rejected'
untrusted_root="$temp_root/untrusted-store"
if substitute "$untrusted_root" "$wrong_key" "$primary_path"   >"$temp_root/untrusted.log" 2>&1; then
  fail "input-addressed path was accepted with an untrusted key"
fi
run grep -F 'lacks a signature by a trusted key' "$temp_root/untrusted.log"

scenario 'content-addressed path and Range'
large_file="$temp_root/large-input"
run dd if=/dev/zero of="$large_file" bs=1048576 count=16 status=none
ca_path=$(nix_cli store add-file "$large_file")
sign_path "$ca_path"
cache_copy_to "$ca_path"
ca_root="$temp_root/ca-store"
substitute "$ca_root" "$wrong_key" "$ca_path"
run cmp "$ca_path" "$ca_root$ca_path"
printf '%s\n' \
  'CA_NOTE content-addressed paths self-authenticate; this is compatibility coverage, not signature-rejection proof'
ca_nar_url=$(nar_url_for "$ca_path")
range_headers="$temp_root/range.headers"
range_body="$temp_root/range.body"
cache_curl --range 0-7 \
  --dump-header "$range_headers" \
  --output "$range_body" \
  "$server_url/$ca_nar_url"
run grep -E '^HTTP/[0-9.]+ 206' "$range_headers"
[[ $(wc -c < "$range_body") -eq 8 ]] || fail "Range response was not eight bytes"

scenario 'negative lookup followed by --refresh'
refresh_path=$(build_path refresh "$nonce")
sign_path "$refresh_path"
refresh_root="$temp_root/refresh-store"
if substitute "$refresh_root" "$trusted_key" "$refresh_path"   >"$temp_root/negative.log" 2>&1; then
  fail "missing path unexpectedly substituted"
fi
cache_copy_to "$refresh_path"
substitute "$refresh_root" "$trusted_key" "$refresh_path"
run cmp "$refresh_path" "$refresh_root$refresh_path"

scenario 'concurrent identical native uploads'
concurrent_path=$(build_path concurrent "$nonce")
sign_path "$concurrent_path"
cache_copy_to "$concurrent_path" >"$temp_root/concurrent-1.log" 2>&1 &
copy_one=$!
cache_copy_to "$concurrent_path" >"$temp_root/concurrent-2.log" 2>&1 &
copy_two=$!
if ! wait "$copy_one"; then
  cat "$temp_root/concurrent-1.log" >&2
  fail "first concurrent upload failed"
fi
if ! wait "$copy_two"; then
  cat "$temp_root/concurrent-2.log" >&2
  fail "second concurrent upload failed"
fi
concurrent_root="$temp_root/concurrent-store"
substitute "$concurrent_root" "$trusted_key" "$concurrent_path"
run cmp "$concurrent_path" "$concurrent_root$concurrent_path"

scenario 'interrupted upload has no partial visibility'
ca_nar_file="$data_dir/$ca_nar_url"
expect_file "$ca_nar_file"
ca_nar_name=${ca_nar_url#nar/}
if [[ "$ca_nar_name" == 0* ]]; then
  interrupted_name=1${ca_nar_name:1}
else
  interrupted_name=0${ca_nar_name:1}
fi
interrupted_url="nar/$interrupted_name"
cache_curl --limit-rate 65536 \
  --upload-file "$ca_nar_file" \
  "$server_url/$interrupted_url" \
  >"$temp_root/interrupted.log" 2>&1 &
interrupted_pid=$!
wait_for_temp "$interrupted_pid"
[[ $(http_status "$server_url/$interrupted_url") == 404 ]] ||
  fail "partial upload became visible"
kill "$interrupted_pid"
wait "$interrupted_pid" || true
[[ $(http_status "$server_url/$interrupted_url") == 404 ]] ||
  fail "interrupted upload became visible"
expect_missing "$data_dir/$interrupted_url"

scenario 'restart during publication'
restart_url="$ca_nar_url"
restart_source="$temp_root/restart.nar"
run mv "$ca_nar_file" "$restart_source"
cache_curl --limit-rate 65536 \
  --upload-file "$restart_source" \
  "$server_url/$restart_url" \
  >"$temp_root/restart-upload.log" 2>&1 &
restart_upload_pid=$!
wait_for_temp "$restart_upload_pid"
[[ $(http_status "$server_url/$restart_url") == 404 ]] ||
  fail "in-progress publication became visible"
crash_server
wait "$restart_upload_pid" || true
start_server
[[ $(http_status "$server_url/$restart_url") == 404 ]] ||
  fail "restart exposed a partial publication"
cache_curl --upload-file "$restart_source" "$server_url/$restart_url"
[[ $(http_status "$server_url/$restart_url") == 200 ]] ||
  fail "retry after restart was not published"
expect_file "$ca_nar_file"

scenario 'corrupt uploaded NAR is rejected'
primary_nar_url=$(nar_url_for "$primary_path")
primary_nar_file="$data_dir/$primary_nar_url"
run cp "$primary_nar_file" "$temp_root/primary.nar.backup"
printf X >> "$primary_nar_file"
corrupt_root="$temp_root/corrupt-store"
if substitute "$corrupt_root" "$trusted_key" "$primary_path"   >"$temp_root/corrupt.log" 2>&1; then
  fail "corrupt NAR substituted successfully"
fi
run mv "$temp_root/primary.nar.backup" "$primary_nar_file"

scenario 'default compression is an explicit v0.1 non-goal'
default_path=$(build_path default-compression "$nonce")
sign_path "$default_path"
if nix_cli copy --refresh --option netrc-file "$netrc" \
  --to "$server_url" "$default_path" \
  >"$temp_root/default-compression.log" 2>&1; then
  fail "v0.1 unexpectedly accepted Nix default compressed upload"
fi
printf 'SKIP default compression: Nix uses .nar.xz; v0.1 intentionally accepts only uncompressed .nar\n'
printf 'SKIP realisations: Nix 2.31.5 emitted no realisation requests in the recorded protocol trace\n'

printf '\nEVIDENCE daemon log\n'
cat "$server_stdout"
cat "$server_log"
metrics_body="$temp_root/metrics"
metrics_status=$(run curl --silent --show-error --netrc-file "$netrc" \
  --output "$metrics_body" --write-out '%{http_code}' "$server_url/metrics")
if [[ "$metrics_status" == 200 ]]; then
  cat "$metrics_body"
elif [[ "$metrics_status" == 404 ]]; then
  printf 'SKIP metrics: the endpoint is scheduled after this baseline in the verification plan\n'
else
  fail "unexpected metrics status: $metrics_status"
fi

printf '\nPASS real-Nix end-to-end verification\n'
