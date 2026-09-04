#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT=""
SIZE_GIB=20
PROFILE_SECONDS=60
JOBS=1
PORT=0
MAX_NAR_BYTES=$((16 * 1024 * 1024 * 1024))

usage() {
  cat <<'EOF'
Usage: scripts/profile-tina.sh [options]

Profile narjar serving real paths from the current Nix system store.

Options:
  --output DIR       Output directory (default: a temporary directory)
  --size-gib N       Minimum NAR size to select (default: 20)
  --seconds N        perf capture duration (default: 60)
  --jobs N           narjar push concurrency (default: 1)
  --port N           Local server port (default: 0, auto-select)
  -h, --help         Show this help

Run from the development shell, for example:
  nix develop --command scripts/profile-tina.sh --size-gib 20
EOF
}

while (($#)); do
  case "$1" in
    --output) OUTPUT=$2; shift 2 ;;
    --size-gib) SIZE_GIB=$2; shift 2 ;;
    --seconds) PROFILE_SECONDS=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    --port) PORT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for command in cargo curl heaptrack heaptrack_print inferno-collapse-perf inferno-flamegraph nix nix-store perf setsid; do
  command -v "$command" >/dev/null || {
    echo "missing '$command'; run this inside 'nix develop'" >&2
    exit 1
  }
done

if command -v doas >/dev/null 2>&1; then
  PERF_RUNNER=(doas -n -- "$(command -v perf)")
  PRIV_RUNNER=(doas -n --)
elif command -v sudo >/dev/null 2>&1; then
  PERF_RUNNER=(sudo -n -- "$(command -v perf)")
  PRIV_RUNNER=(sudo -n --)
else
  PERF_RUNNER=(perf)
  PRIV_RUNNER=()
fi

if [[ -z "$OUTPUT" ]]; then
  OUTPUT=$(mktemp -d /tmp/narjar-profile.XXXXXX)
else
  mkdir -p "$OUTPUT"
  OUTPUT=$(cd "$OUTPUT" && pwd)
fi

exec 3> "$OUTPUT/commands.log"
BASH_XTRACEFD=3
PS4='+ ${BASH_SOURCE}:${LINENO}: '
set -x

while read -r pid; do
  kill -TERM "$pid" 2>/dev/null || true
done < <(pgrep -f '/tmp/narjar-profile\.[^ ]*/target/profiling/narjar serve' || true)
sleep 0.2

TARGET="$OUTPUT/target"
BIN="$TARGET/profiling/narjar"
DATA="$OUTPUT/data"
MANIFEST="$OUTPUT/system-store.tsv"
TARGET_BYTES=$((SIZE_GIB * 1024 * 1024 * 1024))
PROFILE_RUSTFLAGS="-C target-cpu=native -C force-frame-pointers=yes"
SERVER_URI="http://127.0.0.1:$PORT"
CACHE_URI="$SERVER_URI?compression=none"
SERVER_PID=""
PERF_PID=""
HEAPTRACK_PID=""
WORKLOAD_PIDS=()

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$PERF_PID" ]] && kill -0 "$PERF_PID" 2>/dev/null; then
    kill -TERM -- "-$PERF_PID" 2>/dev/null || kill -TERM "$PERF_PID" 2>/dev/null || true
  fi
  if [[ -n "$HEAPTRACK_PID" ]] && kill -0 "$HEAPTRACK_PID" 2>/dev/null; then
    kill -INT -- "-$HEAPTRACK_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
  fi
  for pid in "${WORKLOAD_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT INT TERM

echo "output: $OUTPUT"
echo "cleaning profiling target: $TARGET"
cargo clean --manifest-path "$ROOT/Cargo.toml"
cargo clean --manifest-path "$ROOT/Cargo.toml" --target-dir "$TARGET"

if ((${#PRIV_RUNNER[@]})); then
  printf '%s\n' 0 | "${PRIV_RUNNER[@]}" tee /proc/sys/kernel/kptr_restrict >/dev/null
  printf '%s\n' -1 | "${PRIV_RUNNER[@]}" tee /proc/sys/kernel/perf_event_paranoid >/dev/null
fi

echo "building narjar with the profiling profile, frame pointers, and DWARF"
CARGO_TARGET_DIR="$TARGET" \
  RUSTFLAGS="$PROFILE_RUSTFLAGS" \
  cargo build --manifest-path "$ROOT/Cargo.toml" --profile profiling 2>&1 | tee "$OUTPUT/build.log"

echo "selecting at least ${SIZE_GIB} GiB of real Nix store NARs"
nix path-info --all --json > "$OUTPUT/path-info.json"
python - "$TARGET_BYTES" "$MAX_NAR_BYTES" "$MANIFEST" "$OUTPUT/path-info.json" <<'PY'
import json
import sys

target_bytes = int(sys.argv[1])
max_nar_bytes = int(sys.argv[2])
manifest = sys.argv[3]
path_info = sys.argv[4]

with open(path_info) as source:
    items = json.load(source)

if isinstance(items, dict):
    items = [{"path": path, **info} for path, info in items.items()]

entries = []
for item in items:
    path = item.get("path")
    size = int(item.get("narSize", 0))
    if path and path.startswith("/nix/store/") and 0 < size <= max_nar_bytes:
        entries.append((size, path))

selected = []
total = 0
for size, path in sorted(entries, reverse=True):
    selected.append((path, size))
    total += size
    if total >= target_bytes:
        break

if total < target_bytes:
    raise SystemExit(f"system store has only {total} bytes of usable NARs")

with open(manifest, "w") as output:
    for path, size in selected:
        output.write(f"{path}\t{size}\n")

print(f"selected {len(selected)} paths ({total} bytes)")
PY

PATHS=()
TOTAL_BYTES=0
while IFS=$'\t' read -r path size; do
  PATHS+=("$path")
  TOTAL_BYTES=$((TOTAL_BYTES + size))
done < "$MANIFEST"

nix-store --generate-binary-cache-key narjar-profile "$OUTPUT/secret-key" "$OUTPUT/public-key"
"$BIN" init --data-dir "$DATA"
cp "$OUTPUT/public-key" "$DATA/trusted-public-keys"
TOKEN=$("$BIN" token create --data-dir "$DATA" --scope write)
printf 'machine 127.0.0.1 login narjar password %s\n' "$TOKEN" > "$OUTPUT/profile.netrc"
chmod 600 "$OUTPUT/profile.netrc" "$OUTPUT/secret-key"

start_server() {
  "$BIN" serve \
    --data-dir "$DATA" \
    --listen "127.0.0.1:$PORT" \
    --workers 1 \
    --max-in-flight 64 \
    --max-nar-bytes "$MAX_NAR_BYTES" \
    --min-free-bytes 0 \
    > >(tee "$1") 2>&1 &
  SERVER_PID=$!

  for _ in {1..100}; do
    if [[ "$PORT" == 0 ]]; then
      if [[ -r "$1" ]]; then
        ACTUAL_PORT=$(sed -n 's/^listening http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$1" | head -1)
        if [[ -n "$ACTUAL_PORT" ]]; then
          PORT=$ACTUAL_PORT
          SERVER_URI="http://127.0.0.1:$PORT"
          CACHE_URI="$SERVER_URI?compression=none"
        fi
      fi
    fi
    if curl --fail --silent "http://127.0.0.1:$PORT/healthz" >/dev/null; then
      return
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo "narjar server exited; see $1" >&2
      cat "$1" >&2
      exit 1
    fi
    sleep 0.1
  done

  echo "narjar server did not become ready; see $1" >&2
  exit 1
}

stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

start_perf_server() {
  local log=$1

  setsid "${PERF_RUNNER[@]}" record \
    -o "$OUTPUT/perf.data" \
    -g --call-graph fp -F 997 \
    "$BIN" serve \
      --data-dir "$DATA" \
      --listen "127.0.0.1:$PORT" \
      --workers 1 \
      --max-in-flight 64 \
      --max-nar-bytes "$MAX_NAR_BYTES" \
      --min-free-bytes 0 \
      > >(tee "$log") 2>&1 &
  PERF_PID=$!
  SERVER_PID=$PERF_PID

  for _ in {1..100}; do
    if [[ "$PORT" == 0 ]] && [[ -r "$log" ]]; then
      ACTUAL_PORT=$(sed -n 's/^listening http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$log" | head -1)
      if [[ -n "$ACTUAL_PORT" ]]; then
        PORT=$ACTUAL_PORT
        SERVER_URI="http://127.0.0.1:$PORT"
        CACHE_URI="$SERVER_URI?compression=none"
      fi
    fi
    if curl --fail --silent "http://127.0.0.1:$PORT/healthz" >/dev/null; then
      return
    fi
    if ! kill -0 "$PERF_PID" 2>/dev/null; then
      echo "profiled narjar server exited; see $log" >&2
      cat "$log" >&2
      exit 1
    fi
    sleep 0.1
  done

  echo "profiled narjar server did not become ready; see $log" >&2
  exit 1
}

stop_perf_server() {
  if [[ -n "$PERF_PID" ]] && kill -0 "$PERF_PID" 2>/dev/null; then
    kill -TERM -- "-$PERF_PID" 2>/dev/null || kill -TERM "$PERF_PID" 2>/dev/null || true
    wait "$PERF_PID" 2>/dev/null || true
  fi
  PERF_PID=""
  SERVER_PID=""
}

push_system_store() {
  "$BIN" push \
    --to "$CACHE_URI" \
    --jobs "$JOBS" \
    --refresh \
    --netrc-file "$OUTPUT/profile.netrc" \
    --signing-key-file "$OUTPUT/secret-key" \
    "${PATHS[@]}"
}

prepare_read_workload() {
  local store_hash nar_url
  store_hash=$(basename "${PATHS[0]}" | cut -d- -f1)
  nar_url=$(curl --fail --silent --show-error --no-compressed \
    "$SERVER_URI/$store_hash.narinfo" | awk '$1 == "URL:" { print $2; exit }')
  [[ -n "$nar_url" ]] || { echo "narinfo did not contain a NAR URL" >&2; exit 1; }
  if [[ "$nar_url" == /* ]]; then
    NAR_ENDPOINT="$SERVER_URI$nar_url"
  else
    NAR_ENDPOINT="$SERVER_URI/$nar_url"
  fi
}

run_read_workload() {
  local end=$((SECONDS + PROFILE_SECONDS))
  local reader

  for _ in {1..4}; do
    (
      while ((SECONDS < end)); do
        curl --fail --silent --show-error --no-compressed \
          --max-time 15 -H 'Accept-Encoding: identity' "$NAR_ENDPOINT" >/dev/null || true
      done
    ) &
    WORKLOAD_PIDS+=("$!")
  done

  for _ in {1..8}; do
    (
      while ((SECONDS < end)); do
        curl --fail --silent --show-error --no-compressed \
          --max-time 5 -H 'Accept-Encoding: identity' -H 'Range: bytes=0-1048575' \
          "$NAR_ENDPOINT" >/dev/null || true
        curl --fail --silent --show-error --no-compressed \
          --max-time 5 -H 'Accept-Encoding: identity' -H 'Range: bytes=-1048576' \
          "$NAR_ENDPOINT" >/dev/null || true
      done
    ) &
    WORKLOAD_PIDS+=("$!")
  done

  for reader in "${WORKLOAD_PIDS[@]}"; do
    wait "$reader" 2>/dev/null || true
  done
  WORKLOAD_PIDS=()
}

echo "populating the SSD-backed cache for CPU profile"
start_server "$OUTPUT/flamegraph-populate-server.log"
push_system_store 2>&1 | tee "$OUTPUT/flamegraph-populate.log"
prepare_read_workload
stop_server
PORT=0
SERVER_URI="http://127.0.0.1:$PORT"
CACHE_URI="$SERVER_URI?compression=none"
echo "capturing CPU profile for ${PROFILE_SECONDS}s of sustained reads"
start_perf_server "$OUTPUT/flamegraph-server.log"
prepare_read_workload
run_read_workload 2>&1 | tee "$OUTPUT/flamegraph-workload.log"
stop_perf_server

if [[ ! -r "$OUTPUT/perf.data" ]]; then
  if command -v doas >/dev/null 2>&1; then
    doas -n -- chmod 644 "$OUTPUT/perf.data"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -n -- chmod 644 "$OUTPUT/perf.data"
  fi
fi

perf script -i "$OUTPUT/perf.data" 2> "$OUTPUT/perf-script.log" \
  | tee "$OUTPUT/perf.script" \
  | inferno-collapse-perf \
  | tee "$OUTPUT/perf.folded" \
  | inferno-flamegraph --title "narjar system-store push" \
  > "$OUTPUT/flamegraph.svg"

echo "capturing heaptrack profile with sustained reads"
PORT=0
SERVER_URI="http://127.0.0.1:$PORT"
CACHE_URI="$SERVER_URI?compression=none"
(
  cd "$OUTPUT"
  exec setsid heaptrack \
    "$BIN" serve \
      --data-dir "$DATA" \
      --listen "127.0.0.1:$PORT" \
      --workers 1 \
      --max-in-flight 64 \
      --max-nar-bytes "$MAX_NAR_BYTES" \
      --min-free-bytes 0
) > >(tee "$OUTPUT/heaptrack-server.log") 2>&1 &
HEAPTRACK_PID=$!

READY=0
for _ in {1..100}; do
  if [[ "$PORT" == 0 ]]; then
    if [[ -r "$OUTPUT/heaptrack-server.log" ]]; then
      ACTUAL_PORT=$(sed -n 's/^listening http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$OUTPUT/heaptrack-server.log" | head -1)
      if [[ -n "$ACTUAL_PORT" ]]; then
        PORT=$ACTUAL_PORT
        SERVER_URI="http://127.0.0.1:$PORT"
        CACHE_URI="$SERVER_URI?compression=none"
      fi
    fi
  fi
  if curl --fail --silent "http://127.0.0.1:$PORT/healthz" >/dev/null; then
    READY=1
    break
  fi
  if ! kill -0 "$HEAPTRACK_PID" 2>/dev/null; then
    echo "heaptrack server exited; see $OUTPUT/heaptrack-server.log" >&2
    cat "$OUTPUT/heaptrack-server.log" >&2
    exit 1
  fi
  sleep 0.1
done
if (( ! READY )); then
  echo "heaptrack server did not become ready; see $OUTPUT/heaptrack-server.log" >&2
  exit 1
fi

prepare_read_workload
run_read_workload 2>&1 | tee "$OUTPUT/heaptrack-workload.log"
kill -INT -- "-$HEAPTRACK_PID" 2>/dev/null || true
wait "$HEAPTRACK_PID" 2>/dev/null || true
HEAPTRACK_PID=""

HEAPTRACK_FILE=$(find "$OUTPUT" -maxdepth 1 -type f -name 'heaptrack*.zst' -printf '%p\n' | sort | tail -1)
[[ -n "$HEAPTRACK_FILE" ]] || { echo "heaptrack did not produce a .zst profile" >&2; exit 1; }
heaptrack_print "$HEAPTRACK_FILE" | tee "$OUTPUT/heaptrack.txt"

{
  echo "root=$ROOT"
  echo "git_commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "size_gib=$SIZE_GIB"
  echo "selected_paths=${#PATHS[@]}"
  echo "selected_bytes=$TOTAL_BYTES"
  echo "profile_seconds=$PROFILE_SECONDS"
  echo "jobs=$JOBS"
  echo "rustflags=$PROFILE_RUSTFLAGS"
  echo "cache_uri=$CACHE_URI"
  echo "cargo_profile=profiling"
  echo "cargo_profile_debug=2"
  echo "cargo_profile_strip=false"
} > "$OUTPUT/metadata.txt"

echo "done"
echo "flamegraph: $OUTPUT/flamegraph.svg"
echo "heaptrack:  $HEAPTRACK_FILE"
echo "report:     $OUTPUT/heaptrack.txt"
