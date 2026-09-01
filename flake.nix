{
  description = "Authoritative Nix development and packaging boundary for narjar";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crane = {
      url = "github:ipetkov/crane/v0.20.0";

    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "aarch64-darwin" "x86_64-linux" ];
      forAllSystems = f:
        lib.genAttrs supportedSystems (system:
          let
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ (import rust-overlay) ];
            };
          in
          f pkgs);
    in
    {
      packages = forAllSystems (pkgs:
        let
          toolchain = pkgs.rust-bin.stable."1.85.1".default.override {
            extensions = [ "rust-src" "rust-analyzer-preview" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          src = lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              lib.cleanSourceFilter path type
              || builtins.elem (baseNameOf (toString path)) [
                "flake.nix"
                "flake.lock"
                ".envrc"
                "README.md"
              ];
          };
          commonArgs = {
            inherit src;
            pname = "narjar";
            version = "0.1.0";
            strictDeps = true;
            cargoExtraArgs = "--locked";
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          narjar = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
          });
        in
        {
          inherit cargoArtifacts narjar;
          default = narjar;
        });

      devShells = forAllSystems (pkgs:
        let
          toolchain = pkgs.rust-bin.stable."1.85.1".default.override {
            extensions = [ "rust-src" "rust-analyzer-preview" ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              toolchain
              pkgs.cargo
              pkgs.git
              pkgs.nix
            ];
          };
        });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = lib.getExe self.packages.${pkgs.system}.default;
        };
      });

      checks = forAllSystems (pkgs:
        let
          package = self.packages.${pkgs.system};
          toolchain = pkgs.rust-bin.stable."1.85.1".default.override {
            extensions = [ "rust-src" "rust-analyzer-preview" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          commonArgs = {
            src = lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              lib.cleanSourceFilter path type
              || builtins.elem (baseNameOf (toString path)) [
                "flake.nix"
                "flake.lock"
                ".envrc"
                "README.md"
              ];
          };
            pname = "narjar";
            version = "0.1.0";
            strictDeps = true;
            cargoExtraArgs = "--locked";
          };
        in
        {
          inherit (package) cargoArtifacts;
          cargo-test = craneLib.cargoTest (commonArgs // {
            inherit (package) cargoArtifacts;
          });
        });
    };
}
