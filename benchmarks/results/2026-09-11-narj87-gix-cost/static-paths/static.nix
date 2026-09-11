{
  repoPath ? "/home/mjc/projects/narjar",
  variant,
}:
let
  repo = builtins.getFlake repoPath;
  pkgs = import repo.inputs.nixpkgs {
    system = "x86_64-linux";
    overlays = [ (import repo.inputs.rust-overlay) ];
  };
  target = "x86_64-unknown-linux-musl";
  toolchain = pkgs.rust-bin.stable."1.98.1".default.override { targets = [ target ]; };
  craneLib = (repo.inputs.crane.mkLib pkgs).overrideToolchain toolchain;
  src = builtins.path {
    path = "/tmp/narj87-gix-cost/${variant}";
    name = "narj87-gix-${variant}";
  };
  cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };
in
craneLib.buildPackage {
  inherit src cargoVendorDir;
  pname = "narj87-gix-${variant}-static";
  version = "0.1.0";
  cargoExtraArgs = "--locked --target ${target}";
  CARGO_BUILD_TARGET = target;
  nativeBuildInputs = [ pkgs.pkgsStatic.stdenv.cc ];
  doCheck = false;
}
