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

  configuration = {
    dataDir,
    statsInventoryIntervalSeconds ? null,
    statsZfsDataset ? null,
  }:
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.system;
      modules = [
        module
        base
        {
          services.narjar = {
            enable = true;
            inherit dataDir statsInventoryIntervalSeconds statsZfsDataset;
            minFreeBytes = 0;
            package = package;
          };
        }
      ];
    }).config;

  evaluates = dataDir:
    let
      result = builtins.tryEval (
        (configuration {inherit dataDir;}).system.build.toplevel.drvPath
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
  defaultConfig = configuration {dataDir = "/var/lib/narjar";};
  sampledConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsInventoryIntervalSeconds = 900;
  };
  zfsSampledConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsZfsDataset = "tank/narjar";
  };
  emptyZfsDatasetConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsZfsDataset = "";
  };
in
assert builtins.all evaluates valid;
assert builtins.all (dataDir: !(evaluates dataDir)) invalid;
assert !(lib.hasInfix "--stats-inventory-interval-seconds" defaultConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--stats-inventory-interval-seconds 900" sampledConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert !(lib.hasInfix "--stats-filesystem-sample" defaultConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--stats-filesystem-sample /run/narjar-zfs-stats/sample.json" zfsSampledConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasAttr "narjar-zfs-stats" zfsSampledConfig.systemd.services);
assert (zfsSampledConfig.systemd.timers.narjar-zfs-stats.timerConfig.OnUnitActiveSec == "60s");
assert (!(lib.hasAttr "narjar-zfs-stats" defaultConfig.systemd.services));
assert (!(builtins.tryEval emptyZfsDatasetConfig.system.build.toplevel.drvPath).success);
"narjar module dataDir assertions passed"
