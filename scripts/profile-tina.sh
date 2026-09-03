#!/usr/bin/env bash

set -euo pipefail

if [[ ${1:-} == --profile-child ]]; then
    : "${NARJAR_BIN:?NARJAR_BIN is required}"
    : "${NARJAR_DATA_DIR:?NARJAR_DATA_DIR is required}"
    : "${NARJAR_SECRET_KEY:?NARJAR_SECRET_KEY is required}"
    : "${NARJAR_NETRC:?NARJAR_NETRC is required}"
    : "${NARJAR_SEED_PATH:?NARJAR_SEED_PATH is required}"
    : "${NARJAR_SERVER_LOG:?NARJAR_SERVER_LOG is required}"

    profile_seconds=${NARJAR_PROFILE_SECONDS:-30}
    jobs=${NARJAR_JOBS:-4}
    server_pid=

    cleanup_server() {
        if [[ -n ${server_pid:-} ]]; then
            kill "$server_pid" 2>/dev/null || true
            wait "$server_pid" 2>/dev/null || true
        fi
    }
    trap cleanup_server EXIT

    "$NARJAR_BIN" serve \
        --data-dir "$NARJAR_DATA_DIR" \
        --listen 127.0.0.1:0 \
        --min-free-bytes 0 \
        >"$NARJAR_SERVER_LOG" 2>&1 &
    server_pid=$!

    port=
    for _ in $(seq 1 50); do
        port=$(sed -n 's/^listening http:\/\/127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$NARJAR_SERVER_LOG" | head -1)
        if [[ -n $port ]] && curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null; then
            break
        fi
        if ! kill -0 "$server_pid" 2>/dev/null; then
            cat "$NARJAR_SERVER_LOG"
            exit 1
        fi
        sleep 0.2
    done
    [[ -n $port ]] || {
        cat "$NARJAR_SERVER_LOG"
        exit 1
    }
    base="http://127.0.0.1:$port"

    # The initial push performs real Nix cache writes before the read phase.
    "$NARJAR_BIN" push \
        --to "$base" \
        --jobs "$jobs" \
        --netrc-file "$NARJAR_NETRC" \
        --signing-key-file "$NARJAR_SECRET_KEY" \
        "$NARJAR_SEED_PATH"

    store_hash=$(basename "$NARJAR_SEED_PATH" | cut -d- -f1)
    narinfo=$(curl -fsS "$base/$store_hash.narinfo")
    nar_url=$(awk '$1 == "URL:" { print $2; exit }' <<<"$narinfo")
    [[ -n $nar_url ]] || {
        printf 'narinfo did not contain a NAR URL\n' >&2
        exit 1
    }
    if [[ $nar_url == /* ]]; then
        nar_endpoint="$base$nar_url"
    else
        nar_endpoint="$base/$nar_url"
    fi

    # Keep storage writes in the profile after the initial publish too. Nix's
    # refresh path re-uploads the same real NAR and narinfo, exercising the
    # immutable-identical write path and its temporary-file handling.
    (
        end=$((SECONDS + profile_seconds))
        while ((SECONDS < end)); do
            "$NARJAR_BIN" push \
                --to "$base" \
                --jobs 1 \
                --refresh \
                --netrc-file "$NARJAR_NETRC" \
                --signing-key-file "$NARJAR_SECRET_KEY" \
                "$NARJAR_SEED_PATH" \
                >/dev/null 2>&1 || true
        done
    ) &
    writer_pid=$!

    # Mix metadata, full-file, and range reads across all configured workers.
    reader_pids=()
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
        reader_pids+=("$!")
    done
    for reader_pid in "${reader_pids[@]}"; do
        wait "$reader_pid"
    done
    wait "$writer_pid" 2>/dev/null || true
else
    repository=${NARJAR_REPOSITORY:-https://github.com/mjc/narjar.git}
    ref=${NARJAR_REF:-main}
    profile_seconds=${NARJAR_PROFILE_SECONDS:-30}
    jobs=${NARJAR_JOBS:-4}
    root=$(mktemp -d "${TMPDIR:-/tmp}/narjar-profile.XXXXXX")
    source_dir="$root/src"
    data_dir="$root/data"
    secret_key="$root/profile-secret-key"
    public_key="$root/profile-public-key"
    netrc="$root/profile.netrc"
    profile="$root/narjar-tina-release-storage.samply.json.gz"
    server_log="$root/server.log"

    if command -v sudo >/dev/null 2>&1; then
        sudo_cmd=(sudo -n)
    elif command -v doas >/dev/null 2>&1; then
        sudo_cmd=(doas -n)
    else
        printf 'profile-tina: sudo or doas is required for Linux perf buffers\n' >&2
        exit 1
    fi
    "${sudo_cmd[@]}" true

    printf 'PROFILE_ROOT=%s\n' "$root"
    git clone --depth=1 --branch "$ref" "$repository" "$source_dir"
    cd "$source_dir"
    commit=$(git -C "$source_dir" rev-parse HEAD)
    printf 'SOURCE_COMMIT=%s\n' "$commit"

    nix develop --command bash -lc '
        set -euo pipefail
        export RUSTFLAGS="-C force-frame-pointers=yes -C debuginfo=1"
        export CARGO_PROFILE_RELEASE_DEBUG=1
        cargo build --release --locked --bin narjar
    '
    bin="$source_dir/target/release/narjar"
    [[ -x $bin ]] || {
        printf 'profile-tina: release binary was not built\n' >&2
        exit 1
    }
    printf 'PROFILE_BINARY=%s\n' "$bin"

    if [[ -n ${NARJAR_SEED_PATH:-} ]]; then
        seed_path=$NARJAR_SEED_PATH
    else
        seed_path=$(nix path-info "$(readlink -f "$(command -v bash)")")
    fi
    [[ -d /nix/store ]] && [[ $seed_path == /nix/store/* ]] || {
        printf 'profile-tina: seed must be a Nix store path: %s\n' "$seed_path" >&2
        exit 1
    }
    printf 'SEED_PATH=%s\n' "$seed_path"

    "$bin" init --data-dir "$data_dir"
    "$bin" key generate \
        --name profile \
        --secret-key-file "$secret_key" \
        --public-key-file "$public_key"
    cp "$public_key" "$data_dir/trusted-public-keys"
    token=$("$bin" token create --data-dir "$data_dir" --scope write --name profile)
    printf 'machine 127.0.0.1 login profile password %s\n' "$token" >"$netrc"
    chmod 600 "$netrc"

    self=$(readlink -f "$0")
    "${sudo_cmd[@]}" nix --extra-experimental-features 'nix-command flakes' run nixpkgs#samply -- \
        record \
        --save-only \
        --no-open \
        --unstable-presymbolicate \
        --rate 1000 \
        --profile-name narjar-tina-release-storage \
        --output "$profile" \
        -- \
        env \
        NARJAR_BIN="$bin" \
        NARJAR_DATA_DIR="$data_dir" \
        NARJAR_SECRET_KEY="$secret_key" \
        NARJAR_NETRC="$netrc" \
        NARJAR_SEED_PATH="$seed_path" \
        NARJAR_SERVER_LOG="$server_log" \
        NARJAR_PROFILE_SECONDS="$profile_seconds" \
        NARJAR_JOBS="$jobs" \
        bash "$self" --profile-child

    gzip -t "$profile"
    printf 'PROFILE=%s\n' "$profile"
    ls -lh "$profile" "$root"/*.syms.json 2>/dev/null || true
    gzip -cd "$profile" | jq '{product: .meta.product, interval_ms: .meta.interval, threads: ([.threads[] | .samples.length] | add), markers: ([.threads[] | .markers.length] | add)}'
    printf 'SERVER_LOG:\n'
    cat "$server_log"
    printf 'PROFILE_ROOT_RETAINED=%s\n' "$root"
fi
