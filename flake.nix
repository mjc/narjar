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
    crane.url = "github:ipetkov/crane/v0.20.1";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      rust-overlay,
      ...
    }:
    let
      lib = nixpkgs.lib;
      rustVersion = "1.85.1";
      supportedSystems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      staticTarget = "x86_64-unknown-linux-musl";
      staticSystem = "x86_64-linux";
      containerUser = "65532:65532";
      lockIdentity = builtins.hashFile "sha256" ./flake.lock;
      rustTargetFor = {
        aarch64-darwin = "aarch64-apple-darwin";
        x86_64-linux = "x86_64-unknown-linux-gnu";
      };
      repositorySrc = lib.cleanSourceWith {
        src = ./.;
        filter =
          path: type:
          lib.cleanSourceFilter path type
          && !(lib.hasPrefix (toString ./. + "/benchmarks/results") (toString path));
      };

      mkToolchain =
        pkgs: targets:
        pkgs.rust-bin.stable.${rustVersion}.default.override (
          {
            extensions = [
              "rust-src"
              "rust-analyzer-preview"
            ];
          }
          // lib.optionalAttrs (targets != [ ]) { inherit targets; }
        );

      mkCraneBuild =
        {
          pkgs,
          toolchain,
          cargoExtraArgs ? "--locked",
          extraArgs ? { },
        }:
        let
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
          src = lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              craneLib.filterCargoSources path type
              || toString path == toString ./tests/fixtures/nix-2.31.5-http-v0.1.tsv;
          };
          cargoVendorDir = craneLib.vendorCargoDeps { inherit src; };
          commonArgs = {
            inherit src cargoVendorDir cargoExtraArgs;
            pname = "narjar";
            version = "0.1.0";
            strictDeps = true;
          }
          // extraArgs;
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          narjar = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              doCheck = false;
              meta.mainProgram = "narjar";
            }
          );
        in
        {
          inherit
            craneLib
            src
            cargoVendorDir
            commonArgs
            cargoArtifacts
            narjar
            ;
        };

      mkSystem =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          toolchain = mkToolchain pkgs [ ];
          build = mkCraneBuild { inherit pkgs toolchain; };
          provenance = pkgs.writeShellScriptBin "narjar-provenance" ''
            echo "flake_lock_identity=${lockIdentity}"
            echo "nix_version=$(${pkgs.nix}/bin/nix --version)"
            echo "rust_version=$(${toolchain}/bin/rustc --version)"
            echo "host_system=${system}"
            echo "target_triple=${rustTargetFor.${system}}"
            echo "package=${build.narjar}"
            echo "closure=$(${pkgs.nix}/bin/nix path-info -S ${build.narjar})"
          '';
          nixE2E = pkgs.writeShellApplication {
            name = "narjar-nix-e2e";
            runtimeInputs = [
              build.narjar
              pkgs.coreutils
              pkgs.curl
              pkgs.findutils
              pkgs.gnugrep
              pkgs.nix
            ];
            text = builtins.readFile ./tests/nix-e2e.sh;
          };
          continuationBenchmark = pkgs.writeShellApplication {
            name = "narjar-continuation-benchmark";
            runtimeInputs = [
              build.narjar
              pkgs.coreutils
              pkgs.nix
              pkgs.python3
            ];
            text = ''
              export NARJAR_BIN=${lib.getExe build.narjar}
              exec python3 ${./benchmarks/continuation.py} "$@"
            '';
          };
        in
        build
        // {
          inherit
            pkgs
            toolchain
            provenance
            nixE2E
            continuationBenchmark
            ;
        };

      systems = lib.genAttrs supportedSystems mkSystem;
      static = mkCraneBuild {
        pkgs = systems.${staticSystem}.pkgs;
        toolchain = mkToolchain systems.${staticSystem}.pkgs [ staticTarget ];
        cargoExtraArgs = "--locked --target ${staticTarget}";
        extraArgs = {
          CARGO_BUILD_TARGET = staticTarget;
          nativeBuildInputs = [ systems.${staticSystem}.pkgs.pkgsStatic.stdenv.cc ];
        };
      };
      containerImage = systems.${staticSystem}.pkgs.dockerTools.buildLayeredImage {
        name = "narjar";
        tag = "latest";
        contents = [ static.narjar ];
        extraCommands = ''
          mkdir -p var/lib/narjar
          chmod 0700 var/lib/narjar
        '';
        fakeRootCommands = ''
          chown ${containerUser} var/lib/narjar
        '';
        config = {
          Entrypoint = [ "${static.narjar}/bin/narjar" ];
          Cmd = [
            "serve"
            "--data-dir"
            "/var/lib/narjar"
            "--listen"
            "0.0.0.0:5000"
          ];
          User = containerUser;
          WorkingDir = "/var/lib/narjar";
          ExposedPorts."5000/tcp" = { };
          Volumes."/var/lib/narjar" = { };
        };
      };
      ociImage =
        systems.${staticSystem}.pkgs.runCommand "narjar-oci.tar"
          {
            nativeBuildInputs = [ systems.${staticSystem}.pkgs.skopeo ];
          }
          ''
            skopeo --tmpdir "$NIX_BUILD_TOP" --insecure-policy copy \
              docker-archive:${containerImage} \
              oci-archive:$out:narjar
          '';
    in
    {
      nixosModules.default = import ./nix/module.nix { inherit self; };

      packages =
        lib.mapAttrs (_system: env: {
          narjar = env.narjar;
          default = env.narjar;
          cargo-artifacts = env.cargoArtifacts;
          nix-e2e = env.nixE2E;
          continuation-benchmark = env.continuationBenchmark;
        }) systems
        // {
          ${staticSystem} = {
            narjar = systems.${staticSystem}.narjar;
            default = systems.${staticSystem}.narjar;
            cargo-artifacts = systems.${staticSystem}.cargoArtifacts;
            narjar-static = static.narjar;
            narjar-oci = ociImage;
            static-cargo-artifacts = static.cargoArtifacts;
            nix-e2e = systems.${staticSystem}.nixE2E;
            continuation-benchmark = systems.${staticSystem}.continuationBenchmark;
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
          meta.description = "Run narjar";
        };
        provenance = {
          type = "app";
          program = lib.getExe env.provenance;
          meta.description = "Report the locked Narjar build identity";
        };
        nix-e2e = {
          type = "app";
          program = lib.getExe env.nixE2E;
          meta.description = "Run the real-Nix end-to-end verification";
        };
        continuation-benchmark = {
          type = "app";
          program = lib.getExe env.continuationBenchmark;
          meta.description = "Run the matched bincache continuation benchmark";
        };
      }) systems;

      checks = lib.mapAttrs (
        system: env:
        let
          format =
            env.pkgs.runCommand "narjar-format"
              {
                nativeBuildInputs = [ env.toolchain ];
              }
              ''
                cd ${env.src}
                cargo fmt --all -- --check
                touch $out
              '';
          source-filter = env.pkgs.runCommand "narjar-source-filter" { } ''
            test -f ${repositorySrc}/Cargo.toml
            test -f ${repositorySrc}/Cargo.lock
            test -f ${repositorySrc}/src/main.rs
            test -f ${repositorySrc}/flake.nix
            test -f ${repositorySrc}/flake.lock
            test -f ${repositorySrc}/.envrc
            test -f ${repositorySrc}/README.md
            test -f ${env.src}/tests/fixtures/nix-2.31.5-http-v0.1.tsv
            test ! -e ${repositorySrc}/target
            test ! -e ${repositorySrc}/.direnv
            test ! -e ${repositorySrc}/benchmarks/results
            touch $out
          '';
          lock-consistency = env.pkgs.runCommand "narjar-lock-consistency" { } ''
            test -s ${env.src}/Cargo.lock
            test -s ${repositorySrc}/flake.lock
            touch $out
          '';
          runtime-smoke = env.pkgs.runCommand "narjar-runtime-smoke" { } ''
            mkdir data
            ${env.narjar}/bin/narjar serve \
              --data-dir "$PWD/data" \
              --listen 127.0.0.1:0 \
              --workers 1 > "$out" &
            pid=$!
            trap 'kill "$pid" 2>/dev/null || true' EXIT
            for attempt in $(seq 1 100); do
              grep -q '^listening http://127.0.0.1:' "$out" && break
              kill -0 "$pid"
              sleep 0.05
            done
            grep -q '^listening http://127.0.0.1:' "$out"
            kill -TERM "$pid"
            wait "$pid"
            trap - EXIT
          '';
          runtime-closure = env.pkgs.runCommand "narjar-runtime-closure" { } ''
            if ${env.pkgs.nix}/bin/nix-store -qR ${env.narjar} | grep -Eq '(rustc|cargo-|rust-analyzer|clippy|nix-[0-9])'; then
              exit 1
            fi
            touch $out
          '';
        in
        {
          inherit
            format
            source-filter
            lock-consistency
            runtime-smoke
            runtime-closure
            ;
          cargo-artifacts = env.cargoArtifacts;
          compile = env.narjar;
          clippy = env.craneLib.cargoClippy (
            env.commonArgs
            // {
              inherit (env) cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            }
          );
          tests = env.craneLib.cargoTest (
            env.commonArgs
            // {
              inherit (env) cargoArtifacts;
            }
          );
          docs = env.craneLib.cargoDoc (
            env.commonArgs
            // {
              inherit (env) cargoArtifacts;
            }
          );
          package = env.narjar;
        }
        // lib.optionalAttrs (system == staticSystem) {
          static-cargo-artifacts = static.cargoArtifacts;
          static-package = static.narjar;
          nixos-module = env.pkgs.testers.runNixOSTest (import ./nix/module-test.nix { inherit self; });
          oci-archive =
            env.pkgs.runCommand "narjar-oci-archive"
              {
                nativeBuildInputs = [
                  env.pkgs.jq
                  env.pkgs.skopeo
                ];
              }
              ''
                skopeo --tmpdir "$NIX_BUILD_TOP" --insecure-policy inspect oci-archive:${ociImage} > image.json
                skopeo --tmpdir "$NIX_BUILD_TOP" --insecure-policy inspect --config oci-archive:${ociImage} > config.json
                jq -e '.Architecture == "amd64" and .Os == "linux"' image.json
                jq -e '.config.User == "${containerUser}"' config.json
                touch $out
              '';
          static-elf =
            env.pkgs.runCommand "narjar-static-elf"
              {
                nativeBuildInputs = [
                  env.pkgs.binutils
                  env.pkgs.file
                ];
              }
              ''
                file ${static.narjar}/bin/narjar > $out
                ! readelf -l ${static.narjar}/bin/narjar | grep -q INTERP
                ! readelf -d ${static.narjar}/bin/narjar | grep -q NEEDED
              '';
        }
      ) systems;
    };
}
