{pkgs}:
let
  lib = pkgs.lib;
  package = pkgs.writeShellScriptBin "narjar" "exit 0";
  self = {packages.${pkgs.system}.default = package;};
  module = import ./module.nix {inherit self;};
  base = {
    boot.loader.grub.devices = ["nodev"];
    fileSystems."/" = {
      device = "/dev/vda";
      fsType = "ext4";
    };
    system.stateVersion = "25.11";
  };

  evaluates = dataDir:
    let
      result = builtins.tryEval (
        (import (pkgs.path + "/nixos/lib/eval-config.nix") {
          system = pkgs.system;
          modules = [
            module
            base
            {
              services.narjar = {
                enable = true;
                inherit dataDir;
                minFreeBytes = 0;
                package = package;
              };
            }
          ];
        }).config.system.build.toplevel.drvPath
      );
    in result.success;

  valid = [
    "/var/lib/narjar"
    "/var/lib/nar-jar"
  ];
  invalid = [
    "/"
    "/var/lib"
    "/var/lib/"
    "/var/lib/./"
    "/var/lib/foo/../bar"
    "/var/lib/foo/"
    "/var/lib//foo"
  ];
in
assert builtins.all evaluates valid;
assert builtins.all (dataDir: !(evaluates dataDir)) invalid;
"narjar module dataDir assertions passed"
