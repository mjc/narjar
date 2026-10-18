#!/usr/bin/env bash
set -euo pipefail

# Linux / Nix 2.34.8 acceptance; run outside a Nix build sandbox. Required:
# NARJAR_E2E_BASH=/nix/store/<packaged-bash>/bin/bash (already realised).
# PATH: narjar, nix, nix-store, nix-instantiate, curl, jq, sqlite3, coreutils,
# grep, sed, find, and util-linux (unshare). No nixpkgs evaluation or downloads.
# --prerequisites-only checks namespaces, recipe seeding, signing and real
# private-store builds without Narjar. Full acceptance needs the
# NARJ-131 CLI, durable edge leases honoured by offline GC, and raw edge egress.
# If user namespaces are unavailable, use the same packaged entrypoint and Bash
# path as root for this invocation only; do not change host namespace settings.

prerequisites_only=false
case "${1-}" in
  --prerequisites-only) prerequisites_only=true; shift ;;
  --help)
    printf '%s\n' 'Usage: fail-open-edge-e2e.sh [--prerequisites-only]'
    exit 0 ;;
esac
[[ $# == 0 ]] || { printf 'unknown arguments: %s\n' "$*" >&2; exit 2; }

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
scenario() { printf '\nSCENARIO %s\n' "$*"; }
[[ $(uname -s) == Linux ]] || fail 'Linux chroot-store build namespaces are required'
: "${NARJAR_E2E_BASH:?set to the realised packaged Bash /nix/store/.../bin/bash}"
builder=$NARJAR_E2E_BASH
bash_store=${builder%/bin/bash}
[[ "$bash_store" == /nix/store/* && "$builder" == "$bash_store/bin/bash" && -x "$builder" ]] ||
  fail 'NARJAR_E2E_BASH must be a realised /nix/store/<package>/bin/bash'
for tool in nix nix-store nix-instantiate curl jq sqlite3 timeout unshare mktemp \
  realpath mkdir rm cp chmod date sleep cat cmp grep sed find head wc; do
  command -v "$tool" >/dev/null || fail "missing dependency: $tool"
done
if ! "$prerequisites_only"; then
  command -v narjar >/dev/null || fail 'missing dependency: narjar'
fi

umask 077
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-edge-e2e.XXXXXX")
temp_root=$(realpath "$temp_root")
central_pid=
edge_pid=
central_start=
edge_start=
process_start() {
  local stat
  IFS= read -r stat < "/proc/$1/stat" || return 1
  stat=${stat##*) }
  local -a fields
  read -r -a fields <<< "$stat"
  printf '%s' "${fields[19]}"
}
same_server() {
  local pid=$1 started=$2 command
  [[ -r "/proc/$pid/stat" && -r "/proc/$pid/cmdline" ]] || return 1
  [[ $(process_start "$pid") == "$started" ]] || return 1
  IFS= read -r -d '' command < "/proc/$pid/cmdline" || return 1
  [[ "$command" == "$narjar_bin" ]]
}
# Direct child handles, command and kernel start time are checked before signals.
stop_server() {
  local role=$1 pid started attempt
  case "$role" in
    central) pid=$central_pid; started=$central_start ;;
    edge) pid=$edge_pid; started=$edge_start ;;
    *) fail "unknown server: $role" ;;
  esac
  if [[ -n "$pid" ]]; then
    if same_server "$pid" "$started"; then
      kill -TERM "$pid" 2>/dev/null || true
      for ((attempt = 0; attempt < 100; attempt++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
      done
      if same_server "$pid" "$started"; then
        kill -KILL "$pid" 2>/dev/null || true
      fi
    fi
    wait "$pid" || true
  fi
  case "$role" in central) central_pid= ;; edge) edge_pid= ;; esac
}
cleanup() {
  local status=$?
  trap - EXIT
  stop_server edge
  stop_server central
  if (( status != 0 )); then
    local log
    for log in "$temp_root"/*.log; do
      [[ -f "$log" ]] || continue
      printf '\n--- %s ---\n' "${log##*/}" >&2
      cat "$log" >&2
    done
  fi
  # Only this invocation's unique, canonical mktemp directory is removed.
  # Nix makes imported store directories read-only. Change only directories,
  # never regular files (which may be hard-linked inside a store).
  find "$temp_root" -type d -exec chmod u+rwx {} +
  rm -rf -- "$temp_root"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$temp_root"/{home,tmp,config,cache,state,conf,unused-state,empty-path}
printf 'TEMP_ROOT %s\n' "$temp_root"

# Ignore host/user Nix configuration and inherited NARJAR_* settings. Any Nix
# invocation missing an explicit --store still lands in this private guard store.
cat > "$temp_root/conf/nix.conf" <<'CONFIG'
experimental-features = nix-command read-only-local-store
eval-cache = false
build-users-group =
builders =
builders-use-substitutes = false
sandbox = true
sandbox-fallback = false
sandbox-paths =
extra-sandbox-paths =
substituters =
trusted-substituters =
fallback = false
require-sigs = true
narinfo-cache-positive-ttl = 300
narinfo-cache-negative-ttl = 1
max-jobs = 1
cores = 1
min-free = 0
max-free = 0
connect-timeout = 2
download-attempts = 1
stalled-download-timeout = 3
CONFIG
store_uri() { printf 'local?root=%s' "$(jq -rn --arg p "$1" '$p | @uri')"; }
isolated_env=(env -i PATH="$PATH" HOME="$temp_root/home" TMPDIR="$temp_root/tmp"
  XDG_CONFIG_HOME="$temp_root/config" XDG_CONFIG_DIRS="$temp_root/config"
  XDG_CACHE_HOME="$temp_root/cache" XDG_STATE_HOME="$temp_root/state"
  NIX_CONF_DIR="$temp_root/conf" NIX_USER_CONF_FILES="$temp_root/conf/nix.conf"
  NIX_CONFIG='' NIX_PATH='' NIX_REMOTE="$(store_uri "$temp_root/guard")"
  NIX_STORE_DIR=/nix/store NIX_STATE_DIR="$temp_root/unused-state"
  NIX_LOG_DIR="$temp_root/unused-log" LC_ALL=C)
isolated() { "${isolated_env[@]}" "$@"; }
nx() { local root=$1; shift; isolated timeout 90 nix --store "$(store_uri "$root")" "$@"; }
ns() { local root=$1; shift; isolated timeout 90 nix-store --store "$(store_uri "$root")" "$@"; }
expect_missing() { [[ ! -e "$1" ]] || fail "unexpected existing path: $1"; }

version=$(isolated nix --version)
printf '%s\n' "$version"
[[ "$version" == 'nix (Nix) 2.34.8' ]] || fail 'this harness targets pinned Nix 2.34.8'
scenario 'private-store local-build prerequisite'
if ! isolated timeout 5 unshare --user --map-root-user --mount --pid --fork --net true \
    >"$temp_root/namespaces.log" 2>&1; then
  cat "$temp_root/namespaces.log" >&2
  fail 'user/mount/PID/network namespace probe failed; rerun this entrypoint as root with its packaged PATH and NARJAR_E2E_BASH, without changing host permissions'
fi
producer="$temp_root/producer"
# The host store is only a bootstrap source. read-only=true disables DB writes
# and temporary roots. Never build, sign, add, GC or copy *to* this source.
isolated timeout 90 nix copy \
  --from 'local?read-only=true&state=/nix/var/nix&real=/nix/store' \
  --to "$(store_uri "$producer")" --no-check-sigs "$bash_store" \
  >"$temp_root/bootstrap.log" 2>&1
nonce="$(date +%s)-$$-${temp_root##*.}"
cat > "$temp_root/fixtures.nix" <<'NIX'
{ bashPath, nonce }:
let
  bash = builtins.storePath bashPath;
  mk = name: script: attrs: derivation ({
    name = "narjar-edge-" + name + "-" + nonce;
    system = builtins.currentSystem;
    builder = "${bash}/bin/bash";
    args = [ "-euc" script ];
  } // attrs);
  random = name: mk name ''printf '%s\n' "$nonce:$RANDOM:$RANDOM:$RANDOM" > "$out"'' { inherit nonce; };
  b = random "b";
in {
  probe = mk "probe" ''printf '%s\n' private-build-ok > "$out"'' {};
  inherit b;
  a = mk "a" ''printf '%s\n' "$dependency" > "$out"'' { dependency = b; };
  miss = random "miss";
  hit = random "hit";
  recovery = random "recovery";
}
NIX
instantiate() {
  isolated timeout 30 nix-instantiate --store "$(store_uri "$producer")" \
    "$temp_root/fixtures.nix" --argstr bashPath "$bash_store" --argstr nonce "$nonce" -A "$1"
}
probe_drv=$(instantiate probe)
if ! ns "$producer" --realise "$probe_drv" >"$temp_root/probe.out" 2>"$temp_root/probe.log"; then
  fail 'actual private-store sandbox build failed; inspect the probe log (no host permission changes attempted)'
fi
probe_path=$(<"$temp_root/probe.out")
[[ $(<"$producer$probe_path") == private-build-ok ]] || fail 'private build output is wrong'
expect_missing "$probe_path"
printf '%s\n' 'PASS: real private-store sandbox build; host output absent'

a_drv=$(instantiate a)
b_drv=$(instantiate b)
miss_drv=$(instantiate miss)
hit_drv=$(instantiate hit)
recovery_drv=$(instantiate recovery)
a_path=$(ns "$producer" --query --outputs "$a_drv")
b_path=$(ns "$producer" --query --outputs "$b_drv")
miss_path=$(ns "$producer" --query --outputs "$miss_drv")
hit_path=$(ns "$producer" --query --outputs "$hit_drv")
recovery_path=$(ns "$producer" --query --outputs "$recovery_drv")
# A must carry B's derivation as inputDrvs, not an opaque storePath string.
nx "$producer" derivation show "$a_drv" > "$temp_root/a.drv.json"
jq -e --arg a "${a_drv##*/}" --arg b "${b_drv##*/}" \
  '.derivations[$a].inputs.drvs | has($b)' "$temp_root/a.drv.json" >/dev/null ||
  fail 'A does not have a real inputDrvs dependency on B'
seed_consumer() {
  local root=$1
  nx "$producer" copy --no-check-sigs --to "$(store_uri "$root")" \
    "$a_drv" "$miss_drv" "$hit_drv" "$recovery_drv" >"$temp_root/seed.log" 2>&1
  local path
  for path in "$a_path" "$b_path" "$miss_path" "$hit_path" "$recovery_path"; do
    expect_missing "$root$path"
  done
  [[ -x "$root$builder" ]] || fail 'consumer lacks the packaged builder closure'
}
secret_key="$temp_root/secret-key"
public_key="$temp_root/public-key"
isolated timeout 30 nix key generate-secret --key-name narjar-edge-e2e > "$secret_key"
isolated timeout 30 nix key convert-secret-to-public < "$secret_key" > "$public_key"
trusted_key=$(<"$public_key")
if "$prerequisites_only"; then
  # Exercise the fixture graph and recipe-only seeding independently of Narjar.
  ns "$producer" --realise "$a_drv" >"$temp_root/producer.out" 2>"$temp_root/producer.log"
  nx "$producer" store sign --key-file "$secret_key" "$a_path" "$b_path"
  seed_consumer "$temp_root/probe-consumer"
  ns "$temp_root/probe-consumer" --realise "$a_drv" \
    >"$temp_root/graph.out" 2>"$temp_root/graph.log"
  [[ $(<"$temp_root/probe-consumer$a_path") == "$b_path" ]] || fail 'A lost its reference to B'
  [[ -s "$temp_root/probe-consumer$b_path" ]] || fail 'B did not build locally'
  if cmp -s "$producer$b_path" "$temp_root/probe-consumer$b_path"; then
    fail 'prerequisite consumer reused the producer B output'
  fi
  expect_missing "$a_path"
  expect_missing "$b_path"
  printf '%s\n' 'PASS: recipe-only consumer seed and real A -> B local builds (no edge acceptance run)'
  exit 0
fi

narjar_bin=$(realpath "$(command -v narjar)")
central_dir="$temp_root/central"
edge_dir="$temp_root/edge"
netrc="$temp_root/netrc"
for directory in "$central_dir" "$edge_dir"; do
  isolated timeout 30 "$narjar_bin" init --data-dir "$directory"
  cp "$public_key" "$directory/trusted-public-keys"
done
token=$(isolated timeout 30 "$narjar_bin" token create --data-dir "$central_dir" --scope write --name edge-e2e)
printf 'machine 127.0.0.1\nlogin narjar\npassword %s\n' "$token" > "$netrc"
unset token
central_url=
edge_url=
start_server() {
  local role=$1 listen=$2 pid line='' attempt
  local -a args
  case "$role" in
    central)
      args=(--data-dir "$central_dir" --egress-compression zstd) ;;
    edge)
      args=(--data-dir "$edge_dir" --serve-source read-through
        --edge-upstream "$central_url" --edge-lease-seconds 3600
        --edge-max-fills 2 --edge-timeout-seconds 2 --edge-negative-ttl-seconds 1) ;;
    *) fail "unknown server: $role" ;;
  esac
  # Empty PATH proves the servers need no runtime Nix executable. In particular
  # the edge's native-store paths are absent sentinels, checked after shutdown.
  # Clear the previous run before forking, not in the background child's redirect.
  : > "$temp_root/$role.stdout"
  "${isolated_env[@]}" PATH="$temp_root/empty-path" \
    NIX_REMOTE="$(store_uri "$temp_root/$role-native")" \
    NIX_STORE_DIR="$temp_root/$role-native/store" \
    NIX_STATE_DIR="$temp_root/$role-native/state" \
    "$narjar_bin" serve "${args[@]}" --listen "$listen" --min-free-bytes 0 \
    >"$temp_root/$role.stdout" 2>>"$temp_root/$role.log" &
  pid=$!
  case "$role" in
    central) central_pid=$pid; central_start=$(process_start "$pid") ;;
    edge) edge_pid=$pid; edge_start=$(process_start "$pid") ;;
  esac
  for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -s "$temp_root/$role.stdout" ]]; then
      IFS= read -r line < "$temp_root/$role.stdout" || true
      [[ "$line" == listening\ http://127.0.0.1:* ]] && break
    fi
    kill -0 "$pid" 2>/dev/null || fail "$role exited before reporting its address"
    sleep 0.05
  done
  [[ "$line" == listening\ http://127.0.0.1:* ]] || fail "unexpected $role startup line: $line"
  local url=${line#listening }
  url=${url%% *}
  [[ "$url" =~ ^http://127\.0\.0\.1:[0-9]+$ ]] || fail "unexpected address: $url"
  case "$role" in central) central_url=$url ;; edge) edge_url=$url ;; esac
  printf '%s %s\n' "$role" "$url"
}
http() { isolated curl --silent --show-error --noproxy '*' --connect-timeout 2 --max-time 10 "$@"; }
get() { http --fail "$@"; }
hash_part() { local base=${1##*/}; printf '%s' "${base%%-*}"; }
expect_status() {
  local expected=$1 url=$2; shift 2
  local actual
  actual=$(http --output "$temp_root/http.body" --write-out '%{http_code}' "$@" "$url")
  [[ "$actual" == "$expected" ]] || fail "HTTP $actual, expected $expected: $url"
}
client_build() {
  local root=$1 drv=$2 jobs=$3 log=$4
  # Sole substituter and fallback=false are explicit on every consumer build.
  # Do not add --refresh: disk narinfo TTL behaviour is part of this acceptance.
  ns "$root" --realise "$drv" --max-jobs "$jobs" \
    --option builders '' --option substituters "$edge_url" --option fallback false \
    --option trusted-public-keys "$trusted_key" --option require-sigs true \
    --option narinfo-cache-positive-ttl 300 --option narinfo-cache-negative-ttl 1 \
    >"$log.out" 2>"$log"
}
cache_db="$temp_root/cache/nix/binary-cache-v7.sqlite"
cached_row() {
  [[ -f "$cache_db" ]] || fail 'Nix did not create its private narinfo disk cache'
  isolated sqlite3 -readonly "$cache_db" \
    "SELECT n.present, n.url, n.compression, n.timestamp FROM NARs n JOIN BinaryCaches b ON n.cache=b.id WHERE b.url='$edge_url' AND n.hashPart='$(hash_part "$1")';"
}
metric_count() {
  local route=$1 total=0 value
  get "$edge_url/metrics" > "$temp_root/metrics" || fail 'edge metrics request failed'
  while IFS= read -r value; do
    total=$((total + value))
  done < <(sed -n "s/^narjar_http_requests_total{method=\"GET\",route=\"$route\",status=\"[^\"]*\"} \([0-9][0-9]*\)$/\1/p" "$temp_root/metrics")
  printf '%s' "$total"
}

scenario 'producer builds, signs and natively pushes tiny fixtures to central'
ns "$producer" --realise "$a_drv" "$hit_drv" "$recovery_drv" \
  >"$temp_root/producer.out" 2>"$temp_root/producer.log"
nx "$producer" store sign --key-file "$secret_key" "$a_path" "$b_path" "$hit_path" "$recovery_path"
ns "$producer" --query --references "$a_path" | grep -Fx "$b_path" >/dev/null || fail 'A output lost its Nix reference to B'
start_server central 127.0.0.1:0
isolated timeout 60 env PATH="$temp_root/empty-path" \
  NIX_STORE_DIR="$producer/nix/store" NIX_STATE_DIR="$producer/nix/var/nix" \
  "$narjar_bin" push --to "$central_url" --netrc-file "$netrc" --insecure-http \
  --compression zstd "$a_path" "$hit_path" "$recovery_path" >"$temp_root/push.log" 2>&1
start_server edge 127.0.0.1:0

scenario 'warm only A from the A -> B closure'
get "$edge_url/$(hash_part "$a_path").narinfo" > "$temp_root/a.narinfo"
grep -Fx 'Compression: none' "$temp_root/a.narinfo" >/dev/null || fail 'edge did not normalise to raw'
grep -Fx "References: ${b_path##*/}" "$temp_root/a.narinfo" >/dev/null || fail 'edge lost A reference metadata'
expect_missing "$edge_dir/$(hash_part "$b_path").narinfo"

scenario 'prime a real positive Nix disk-cache entry without fetching its output'
isolated timeout 30 nix --store "$edge_url" path-info "$hit_path" >"$temp_root/prime.out" 2>"$temp_root/prime.log"
positive_before=$(cached_row "$hit_path")
IFS='|' read -r present hit_nar compression positive_time <<< "$positive_before"
[[ "$present" == 1 && "$compression" == none && "$hit_nar" =~ ^nar/[0-9a-z]+\.nar$ ]] ||
  fail "unexpected positive disk cache row: $positive_before"
nx "$producer" store dump-path "$hit_path" > "$temp_root/hit.expected.nar"
consumer="$temp_root/consumer"
seed_consumer "$consumer"
stop_server central

scenario 'incomplete cached closure builds A and B locally with fallback=false'
client_build "$consumer" "$a_drv" 1 "$temp_root/closure.log"
[[ $(<"$consumer$a_path") == "$b_path" ]] || fail 'consumer A does not retain B'
[[ -s "$consumer$b_path" ]] || fail 'consumer B is absent'
grep -F "building '$a_drv'" "$temp_root/closure.log" >/dev/null || fail 'A was not built locally'
grep -F "building '$b_drv'" "$temp_root/closure.log" >/dev/null || fail 'B was not built locally'
if cmp -s "$producer$b_path" "$consumer$b_path"; then
  fail 'consumer B reused the producer nonce instead of building locally'
fi

scenario 'uncached central-down miss builds locally with fallback=false'
expect_status 404 "$edge_url/$(hash_part "$miss_path").narinfo"
client_build "$consumer" "$miss_drv" 1 "$temp_root/miss.log"
[[ -s "$consumer$miss_path" ]] || fail 'central-down miss did not build locally'
grep -F "building '$miss_drv'" "$temp_root/miss.log" >/dev/null || fail 'miss was not built locally'

scenario 'restart and offline GC preserve the advertised payload lease'
saved_edge_url=$edge_url
stop_server edge
isolated timeout 30 "$narjar_bin" gc --data-dir "$edge_dir" --target-bytes 0 \
  --min-age-seconds 0 --apply --json >"$temp_root/gc.json" 2>"$temp_root/gc.log"
jq -e '.dry_run == false and .before_bytes > 0 and .protected > 0 and
  .deleted_narinfos == 0 and .deleted_nars == 0' "$temp_root/gc.json" >/dev/null ||
  fail 'offline GC did not retain the advertised objects under pressure'
start_server edge "${saved_edge_url#http://}"
[[ "$edge_url" == "$saved_edge_url" ]] || fail 'edge restart changed the substituter URL'
[[ $(cached_row "$hit_path") == "$positive_before" ]] || fail 'positive disk cache was not preserved'
(( $(date +%s) - positive_time < 300 )) || fail 'positive cache entry expired before the retention test'

scenario 'cached payload GET, HEAD and range work without a new narinfo lookup'
narinfo_before=$(metric_count narinfo)
get "$edge_url/$hit_nar" > "$temp_root/hit.actual.nar"
cmp "$temp_root/hit.expected.nar" "$temp_root/hit.actual.nar"
get --head "$edge_url/$hit_nar" > "$temp_root/head.headers"
grep -E '^HTTP/[0-9.]+ 200' "$temp_root/head.headers" >/dev/null
get --range 0-7 --dump-header "$temp_root/range.headers" \
  "$edge_url/$hit_nar" > "$temp_root/range.body"
grep -E '^HTTP/[0-9.]+ 206' "$temp_root/range.headers" >/dev/null
head -c 8 "$temp_root/hit.expected.nar" > "$temp_root/range.expected"
cmp "$temp_root/range.expected" "$temp_root/range.body"
[[ $(metric_count narinfo) == "$narinfo_before" ]] || fail 'payload-only requests queried metadata'

scenario 'Nix uses its cached positive after restart/GC with central down'
nar_before=$(metric_count nar)
client_build "$consumer" "$hit_drv" 0 "$temp_root/hit.log"
cmp "$producer$hit_path" "$consumer$hit_path"
[[ $(metric_count narinfo) == "$narinfo_before" ]] || fail 'Nix re-queried narinfo instead of using its retained positive'
(( $(metric_count nar) > nar_before )) || fail 'Nix did not GET the retained payload'
[[ $(cached_row "$hit_path") == "$positive_before" ]] || fail 'Nix refreshed its positive metadata'

scenario 'central recovery becomes visible after short negative TTLs, without refresh'
if isolated timeout 30 nix --store "$edge_url" path-info "$recovery_path" \
    >"$temp_root/negative.out" 2>"$temp_root/negative.log"; then
  fail 'central-down uncached recovery fixture unexpectedly exists'
fi
negative_row=$(cached_row "$recovery_path")
[[ "$negative_row" == 0\|* ]] || fail 'Nix did not retain a negative narinfo entry'
start_server central "${central_url#http://}"
# Both Nix and the edge use a one-second negative TTL; cross the integer clock
# boundary as well. Keep the same XDG cache, edge process and endpoint.
sleep 2
client_build "$consumer" "$recovery_drv" 0 "$temp_root/recovery.log"
cmp "$producer$recovery_path" "$consumer$recovery_path"
[[ $(cached_row "$recovery_path") == 1\|* ]] || fail 'negative entry did not become positive'

scenario 'edge rejects writes and owns no native Nix store/database'
expect_status 405 "$edge_url/$hit_nar" --request PUT --data-binary @"$temp_root/hit.expected.nar"
expect_status 405 "$edge_url/$(hash_part "$hit_path").narinfo" --request PUT --data-binary @"$temp_root/a.narinfo"
stop_server edge
stop_server central
expect_missing "$temp_root/edge-native"
expect_missing "$edge_dir/nix"
[[ -z $(find "$edge_dir" -name db.sqlite -print -quit) ]] || fail 'edge created a native Nix database'
for path in "$probe_path" "$a_path" "$b_path" "$miss_path" "$hit_path" "$recovery_path"; do
  expect_missing "$path"
done
printf '\nPASS: fail-open edge real-Nix acceptance (fallback=false, positive TTL 300s, negative TTL 1s)\n'
