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
    statsInventory ? false,
    statsInventoryIntervalSeconds ? 900,
    statsZfsDataset ? null,
    statsFilesystemSample ? null,
    cachePriority ? 30,
    privateRead ? false,
    ioTimeoutSeconds ? 30,
    egressCompression ? "none",
    storageBackend ? "flat",
    readTokens ? null,
    gc ? {},
  }:
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.system;
      modules = [
        module
        base
        {
          services.narjar = {
            enable = true;
            inherit
              dataDir
              statsInventory
              statsInventoryIntervalSeconds
              statsZfsDataset
              statsFilesystemSample
              cachePriority
              privateRead
              ioTimeoutSeconds
              egressCompression
              storageBackend
              ;
            auth.readTokens = readTokens;
            inherit gc;
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
    statsInventory = true;
  };
  customIntervalConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsInventory = true;
    statsInventoryIntervalSeconds = 30;
  };
  zfsSampledConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsZfsDataset = "tank/narjar";
  };
  externallySampledConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsFilesystemSample = "/run/filesystem/sample.json";
  };
  emptyZfsDatasetConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsZfsDataset = "";
  };
  customRuntimeConfig = configuration {
    dataDir = "/var/lib/narjar";
    cachePriority = 42;
    privateRead = true;
    readTokens = "/run/narjar/read.tokens";
    ioTimeoutSeconds = 9;
    egressCompression = "zstd";
    storageBackend = "chunked";
    gc = {
      enable = true;
      maxBytes = 1000;
    };
  };
  invalidCompressionConfig = configuration {
    dataDir = "/var/lib/narjar";
    egressCompression = "brotli";
  };
  missingPrivateReadTokenConfig = configuration {
    dataDir = "/var/lib/narjar";
    privateRead = true;
  };
  conflictingFilesystemSamplesConfig = configuration {
    dataDir = "/var/lib/narjar";
    statsZfsDataset = "tank/narjar";
    statsFilesystemSample = "/run/filesystem/sample.json";
  };
in
assert builtins.all evaluates valid;
assert builtins.all (dataDir: !(evaluates dataDir)) invalid;
assert !(lib.hasInfix "--stats-inventory-interval-seconds" defaultConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--stats-inventory-interval-seconds 900" sampledConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--stats-inventory-interval-seconds 30" customIntervalConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert !(lib.hasInfix "--stats-filesystem-sample" defaultConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--stats-filesystem-sample /run/narjar-zfs-stats/sample.json" zfsSampledConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--stats-filesystem-sample /run/filesystem/sample.json" externallySampledConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasAttr "narjar-zfs-stats" zfsSampledConfig.systemd.services);
assert (zfsSampledConfig.systemd.timers.narjar-zfs-stats.timerConfig.OnUnitActiveSec == "60s");
assert (!(lib.hasAttr "narjar-zfs-stats" defaultConfig.systemd.services));
assert (!(builtins.tryEval emptyZfsDatasetConfig.system.build.toplevel.drvPath).success);
assert (lib.hasInfix "--priority 42" customRuntimeConfig.systemd.services.narjar.preStart);
assert (lib.hasInfix "--private-read" customRuntimeConfig.systemd.services.narjar.preStart);
assert (lib.hasInfix "--storage-backend chunked" customRuntimeConfig.systemd.services.narjar.preStart);
assert (lib.hasInfix "--io-timeout-seconds 9" customRuntimeConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--egress-compression zstd" customRuntimeConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--storage-backend chunked" customRuntimeConfig.systemd.services.narjar.serviceConfig.ExecStart);
assert (lib.hasInfix "--storage-backend chunked" customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.ExecStart);
assert (!(builtins.tryEval invalidCompressionConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval missingPrivateReadTokenConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval conflictingFilesystemSamplesConfig.system.build.toplevel.drvPath).success);
"narjar module dataDir assertions passed"
