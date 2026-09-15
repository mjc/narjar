{ pkgs, ... }:

{
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  packages = with pkgs; [
    git
    nix
    jq
    direnv
    nix-direnv
  ] ++ lib.optionals stdenv.isLinux [
    perf
    inferno
    cargo-flamegraph
    heaptrack
    wrk
    vmtouch
  ];
}
