{
  description = "Authoritative Nix development and packaging boundary for narjar";

  nixConfig = {
    extra-substituters = [ "https://crane.cachix.org" ];
    extra-trusted-public-keys = [
      "crane.cachix.org-1:8Scfpmn9w+hGdXH/Q9tTLiYAE/2dnJYRJP7kl80GuRk="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crane.url = "github:ipetkov/crane/v0.20.0";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "aarch64-darwin" "x86_64-linux" ];
      staticTarget = "x86_64-unknown-linux-musl";
      staticSystem = "x86_64-linux";
      lockIdentity = if self ? narHash then self.narHash else "working-tree";

      sourceFilter = path: type:
        lib.cleanSourceFilter path type
        || builtins.elem (baseNameOf (toString path)) [
          "flake.nix"
          "flake.lock"
          ".envrc"
          "README.md"
        ];

      mkSystem = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          toolchain = pkgs.rust-bin.stable."1.85.1".default.override {
            extensions = [ "rust-src" "rust-analyzer-preview" ];
          };
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          src = lib.cleanSourceWith {
            src = ./.;
            filter = sourceFilter;
          };
          cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };
          commonArgs = {
            inherit src cargoVendorDir;
            pname = "narjar";
            version = "0.1.0";
            strictDeps = true;
            cargoExtraArgs = "--locked";
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          narjar = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
            meta.mainProgram = "narjar";
          });
          provenance = pkgs.writeShellScriptBin "narjar-provenance" ''
            echo "flake_lock_identity=${lockIdentity}"
            echo "nix_version=$(${pkgs.nix}/bin/nix --version)"
            echo "rust_version=$(${toolchain}/bin/rustc --version)"
            echo "host_system=${system}"
            echo "target_triple=${system}"
            echo "package=${narjar}"
            echo "closure=$(${pkgs.nix}/bin/nix path-info -S ${narjar})"
          '';
        in
        {
          inherit pkgs toolchain craneLib src cargoVendorDir commonArgs cargoArtifacts narjar provenance;
        };

      systems = lib.genAttrs supportedSystems mkSystem;

      mkStatic = env:
        let
          toolchain = env.pkgs.rust-bin.stable."1.85.1".default.override {
            extensions = [ "rust-src" "rust-analyzer-preview" ];
            targets = [ staticTarget ];
          };
          craneLib = (crane.mkLib env.pkgs).overrideToolchain toolchain;
          cargoVendorDir = craneLib.vendorCargoDeps { src = env.src; };
          commonArgs = env.commonArgs // {
            inherit cargoVendorDir;
            cargoExtraArgs = "--locked --target ${staticTarget}";
            CARGO_BUILD_TARGET = staticTarget;
            nativeBuildInputs = [ env.pkgs.pkgsStatic.stdenv.cc ];
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          narjar = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            doCheck = false;
            meta.mainProgram = "narjar";
          });
        in
        {
          inherit cargoArtifacts narjar;
        };

      static = mkStatic systems.${staticSystem};
    in
    {
      packages = lib.mapAttrs (_system: env: {
        narjar = env.narjar;
        default = env.narjar;
        cargo-artifacts = env.cargoArtifacts;
      }) systems // {
        ${staticSystem} = {
          narjar = systems.${staticSystem}.narjar;
          default = systems.${staticSystem}.narjar;
          cargo-artifacts = systems.${staticSystem}.cargoArtifacts;
          narjar-static = static.narjar;
          static-cargo-artifacts = static.cargoArtifacts;
        };
      };

      devShells = lib.mapAttrs (_system: env: {
        default = env.pkgs.mkShell {
          packages = [
            env.toolchain
            env.pkgs.git
            env.pkgs.nix
            env.pkgs.direnv
            env.pkgs.nix-direnv
          ];
        };
      }) systems;

      apps = lib.mapAttrs (_system: env: {
        default = {
          type = "app";
          program = lib.getExe' env.narjar "narjar";
        };
        provenance = {
          type = "app";
          program = lib.getExe env.provenance;
        };
      }) systems;

      checks = lib.mapAttrs (system: env:
        let
          format = env.pkgs.runCommand "narjar-format" {
            nativeBuildInputs = [ env.toolchain ];
          } ''
            cd ${env.src}
            cargo fmt --all -- --check
            touch $out
          '';
          source-filter = env.pkgs.runCommand "narjar-source-filter" {} ''
            test -f ${env.src}/Cargo.toml
            test -f ${env.src}/Cargo.lock
            test -f ${env.src}/src/main.rs
            test -f ${env.src}/tests/flake_contract.rs
            test -f ${env.src}/flake.nix
            test -f ${env.src}/flake.lock
            test -f ${env.src}/.envrc
            test -f ${env.src}/README.md
            test ! -e ${env.src}/target
            test ! -e ${env.src}/.direnv
            touch $out
          '';
          lock-consistency = env.pkgs.runCommand "narjar-lock-consistency" {} ''
            test -s ${env.src}/Cargo.lock
            test -s ${env.src}/flake.lock
            touch $out
          '';
          runtime-smoke = env.pkgs.runCommand "narjar-runtime-smoke" {} ''
            ${env.narjar}/bin/narjar > $out
          '';
          runtime-closure = env.pkgs.runCommand "narjar-runtime-closure" {} ''
            if ${env.pkgs.nix}/bin/nix-store -qR ${env.narjar} | grep -Eq '(rustc|cargo-|rust-analyzer|clippy|nix-[0-9])'; then
              exit 1
            fi
            touch $out
          '';
        in
        {
          inherit format source-filter lock-consistency runtime-smoke runtime-closure;
          cargo-artifacts = env.cargoArtifacts;
          compile = env.craneLib.cargoClippy (env.commonArgs // {
            inherit (env) cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          clippy = env.craneLib.cargoClippy (env.commonArgs // {
            inherit (env) cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });
          tests = env.craneLib.cargoTest (env.commonArgs // {
            inherit (env) cargoArtifacts;
          });
          docs = env.craneLib.cargoDoc (env.commonArgs // {
            inherit (env) cargoArtifacts;
          });
          package = env.narjar;
        }
        // lib.optionalAttrs (system == staticSystem) {
          static-cargo-artifacts = static.cargoArtifacts;
          static-package = static.narjar;
          static-elf = env.pkgs.runCommand "narjar-static-elf" {
            nativeBuildInputs = [ env.pkgs.binutils env.pkgs.file ];
          } ''
            file ${static.narjar}/bin/narjar > $out
            ! readelf -l ${static.narjar}/bin/narjar | grep -q INTERP
            ! readelf -d ${static.narjar}/bin/narjar | grep -q NEEDED
          '';
        }) systems;
    };
}

