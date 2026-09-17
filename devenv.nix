{ pkgs, ... }:

let
  fuzzToolchain = pkgs.rust-bin.nightly."2026-09-11".default;
in
{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    git
    nix
    jq
    sqlite
    curl
    cargo-nextest
    shellcheck
    cargo-fuzz
    # cargo-fuzz requires nightly-only compiler flags. Keep this snapshot
    # separate from the stable toolchain used for normal builds.
    fuzzToolchain
  ] ++ lib.optionals stdenv.isLinux [
    util-linux
    perf
    inferno
    heaptrack
    wrk
    vmtouch
  ];

  env.NARJAR_FUZZ_RUSTC = "${fuzzToolchain}/bin/rustc";

  tasks."check:fmt".exec = ''
    cargo fmt --all -- --check
    cargo fmt --manifest-path scripts/nar-corpus/Cargo.toml --all -- --check
  '';
  tasks."check:clippy".exec = "cargo clippy --all-targets --all-features";
  tasks."check:test".exec = "cargo test --locked";
  tasks."check:corpus".exec = "cargo test --locked --manifest-path scripts/nar-corpus/Cargo.toml --target-dir target";
  tasks."check:nextest".exec = "cargo nextest run --locked";
  tasks."check:shell".exec = "shellcheck -S error $(find scripts tests -maxdepth 1 -type f -perm -u+x -print)";
  tasks."check:flake".exec = "nix flake check -L --no-update-lock-file";

  tasks."fuzz:list".exec = "cargo fuzz list";
  tasks."fuzz:build".exec = "RUSTC=\"$NARJAR_FUZZ_RUSTC\" cargo fuzz build nar_decode";

  processes.narjar.exec = ''
    data_dir="$DEVENV_STATE/narjar-data"
    mkdir -p "$data_dir"
    needs_init=false
    for directory in nar nar/.tmp .tmp realisations realisations/.tmp auth; do
      if [ ! -d "$data_dir/$directory" ]; then
        needs_init=true
        break
      fi
    done
    for file in nix-cache-info trusted-public-keys auth/write.tokens; do
      if [ ! -f "$data_dir/$file" ]; then
        needs_init=true
        break
      fi
    done
    if [ ! -f "$data_dir/.narjar-clean" ] && [ ! -f "$data_dir/.narjar-recovery" ]; then
      needs_init=true
    fi
    if [ "$needs_init" = true ]; then
      cargo run --quiet --bin narjar -- init --data-dir "$data_dir"
    fi
    exec cargo run --quiet --bin narjar -- serve --data-dir "$data_dir" --listen 127.0.0.1:5000
  '';
}
