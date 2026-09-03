#!/usr/bin/env bash

set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    printf 'profile-tina: Linux perf is required\n' >&2
    exit 1
fi

repository=${NARJAR_REPOSITORY:-https://github.com/mjc/narjar.git}
ref=${NARJAR_REF:-main}
profiler=${NARJAR_PROFILER:-perf}
profile_seconds=${NARJAR_PROFILE_SECONDS:-30}
perf_warmup_seconds=${NARJAR_PERF_WARMUP_SECONDS:-15}
jobs=${NARJAR_JOBS:-4}
root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-profile.XXXXXX")
source_dir="$root/src"
data_dir="$root/data"
secret_key="$root/profile-secret-key"
public_key="$root/profile-public-key"
netrc="$root/profile.netrc"
perf_data="$root/perf.data"
heaptrack_data="$root/heaptrack"
folded="$root/narjar-tina-release-storage.folded"
flamegraph="$root/narjar-tina-release-storage.svg"
perf_log="$root/perf.log"
report="$root/perf-report.txt"
server_log="$root/server.log"
server_pid=
debuggee_pid=
perf_pid=
reader_pids=()
writer_pid=

case "$profiler" in
    perf|heaptrack) ;;
    *)
        printf 'profile-tina: profiler must be perf or heaptrack\n' >&2
        exit 1
        ;;
esac

sudo_cmd=()
if [[ $profiler == perf ]]; then
    if command -v sudo >/dev/null 2>&1; then
        sudo_cmd=(sudo -n)
    elif command -v doas >/dev/null 2>&1; then
        sudo_cmd=(doas -n)
    else
        printf 'profile-tina: sudo or doas is required for perf\n' >&2
        exit 1
    fi
    "${sudo_cmd[@]}" true
fi

cleanup() {
    for pid in "${reader_pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    if [[ -n ${writer_pid:-} ]]; then
        kill "$writer_pid" 2>/dev/null || true
    fi
    if [[ -n ${perf_pid:-} ]]; then
        "${sudo_cmd[@]}" kill "$perf_pid" 2>/dev/null || true
        wait "$perf_pid" 2>/dev/null || true
    fi
    if [[ -n ${debuggee_pid:-} ]]; then
        kill "$debuggee_pid" 2>/dev/null || true
    fi
    if [[ -n ${server_pid:-} ]]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

printf 'PROFILE_ROOT=%s\n' "$root"
git clone --depth=1 --branch "$ref" "$repository" "$source_dir"
cd "$source_dir"
printf 'SOURCE_COMMIT=%s\n' "$(git rev-parse HEAD)"

nix develop --command bash -lc '
    set -euo pipefail
    export RUSTFLAGS="-C force-frame-pointers=yes -C debuginfo=1"
    export CARGO_PROFILE_RELEASE_DEBUG=1
    cargo build --release --locked --bin narjar
'
bin="$source_dir/target/release/narjar"
[[ -x $bin ]] || { printf 'profile-tina: release build failed\n' >&2; exit 1; }
printf 'PROFILE_BINARY=%s\n' "$bin"

if [[ -n ${NARJAR_SEED_PATH:-} ]]; then
    seed_path=$NARJAR_SEED_PATH
else
    seed_path=$(nix path-info "$(readlink -f "$(command -v bash)")")
fi
[[ $seed_path == /nix/store/* ]] || {
    printf 'profile-tina: seed must be a Nix store path: %s\n' "$seed_path" >&2
    exit 1
}
printf 'SEED_PATH=%s\n' "$seed_path"

"$bin" init --data-dir "$data_dir"
"$bin" key generate --name profile --secret-key-file "$secret_key" --public-key-file "$public_key"
cp "$public_key" "$data_dir/trusted-public-keys"
token=$("$bin" token create --data-dir "$data_dir" --scope write --name profile)
printf 'machine 127.0.0.1 login profile password %s\n' "$token" >"$netrc"
chmod 600 "$netrc"

if [[ $profiler == heaptrack ]]; then
    heaptrack --record-only -o "$heaptrack_data" "$bin" serve --data-dir "$data_dir" \
        --listen 127.0.0.1:0 --min-free-bytes 0 >"$server_log" 2>&1 &
    server_pid=$!
else
    "$bin" serve --data-dir "$data_dir" --listen 127.0.0.1:0 --min-free-bytes 0 >"$server_log" 2>&1 &
    server_pid=$!
    debuggee_pid=$server_pid
fi
port=
for _ in $(seq 1 50); do
    if [[ $profiler == heaptrack ]]; then
        debuggee_pid=$(ps -eo pid=,args= | awk -v bin="$bin" -v data_dir="$data_dir" \
            'index($0, data_dir) && $2 == bin && $3 == "serve" { print $1; exit }')
    fi
    port=$(sed -n 's/^listening http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$server_log" | head -1)
    if [[ -n $port && -n $debuggee_pid ]] && curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log"
        exit 1
    fi
    sleep 0.2
done
[[ -n $port ]] || { cat "$server_log"; exit 1; }
base="http://127.0.0.1:$port"

capture_seconds=$((profile_seconds + perf_warmup_seconds))
if [[ $profiler == perf ]]; then
    "${sudo_cmd[@]}" nix develop --command bash -lc \
        "perf record -F 999 --call-graph fp -p $debuggee_pid -o '$perf_data' -- sleep $capture_seconds" \
        >"$perf_log" 2>&1 &
    perf_pid=$!
    sleep 1
fi

# The initial push performs real Nix cache writes into the isolated store.
"$bin" push --to "$base" --jobs "$jobs" --netrc-file "$netrc" --signing-key-file "$secret_key" "$seed_path"
store_hash=$(basename "$seed_path" | cut -d- -f1)
narinfo=$(curl -fsS "$base/$store_hash.narinfo")
nar_url=$(awk '$1 == "URL:" { print $2; exit }' <<<"$narinfo")
[[ -n $nar_url ]] || { printf 'narinfo did not contain a NAR URL\n' >&2; exit 1; }
if [[ $nar_url == /* ]]; then
    nar_endpoint="$base$nar_url"
else
    nar_endpoint="$base/$nar_url"
fi

# Refresh writes and metadata/full/range reads keep the server busy.
(
    end=$((SECONDS + profile_seconds))
    while ((SECONDS < end)); do
        "$bin" push --to "$base" --jobs 1 --refresh --netrc-file "$netrc" \
            --signing-key-file "$secret_key" "$seed_path" >/dev/null 2>&1 || true
    done
) &
writer_pid=$!

for _ in $(seq 1 8); do
    (
        end=$((SECONDS + profile_seconds))
        while ((SECONDS < end)); do
            curl -fsS "$base/$store_hash.narinfo" >/dev/null
            curl -fsS "$nar_endpoint" >/dev/null
            curl -fsS -H 'Range: bytes=0-1048575' "$nar_endpoint" >/dev/null
            curl -fsS -H 'Range: bytes=-1048576' "$nar_endpoint" >/dev/null
        done
    ) &
    reader_pids+=( "$!" )
done
for reader_pid in "${reader_pids[@]}"; do
    wait "$reader_pid"
done
wait "$writer_pid" 2>/dev/null || true
writer_pid=

if [[ $profiler == perf ]]; then
    wait "$perf_pid"
    perf_pid=

    "${sudo_cmd[@]}" chmod 644 "$perf_data"

    "${sudo_cmd[@]}" nix develop --command bash -lc \
        "perf script -i '$perf_data' | inferno-collapse-perf > '$folded' && inferno-flamegraph < '$folded' > '$flamegraph' && perf report --stdio --no-children --sort comm,dso,symbol -i '$perf_data'" \
        >"$report" 2>&1

    printf 'PERF_DATA=%s\n' "$perf_data"
    printf 'FOLDED_STACKS=%s\n' "$folded"
    printf 'FLAMEGRAPH=%s\n' "$flamegraph"
    printf 'PERF_REPORT=%s\n' "$report"
    ls -lh "$perf_data" "$folded" "$flamegraph" "$report"
else
    kill -TERM "$debuggee_pid"
    wait "$server_pid"
    server_pid=
    debuggee_pid=
    heaptrack_file="$heaptrack_data.zst"
    nix develop --command heaptrack_print --file "$heaptrack_file" \
        --print-peaks 1 --print-allocators 1 --print-temporary 1 \
        --peak-limit 20 --sub-peak-limit 3 >"$report"

    printf 'HEAPTRACK_DATA=%s\n' "$heaptrack_file"
    printf 'HEAPTRACK_REPORT=%s\n' "$report"
    ls -lh "$heaptrack_file" "$report"
fi
sed -n '1,80p' "$report"
printf 'SERVER_LOG:\n'
cat "$server_log"
printf 'PERF_LOG:\n'
cat "$perf_log"
printf 'PROFILE_ROOT_RETAINED=%s\n' "$root"
