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
    dynamicUser ? true,
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
    nativeStoreEnable ? false,
    nativeStateDir ? "/nix/var/nix",
    nativeRootsDir ? "/nix/var/nix/gcroots/auto/narjar",
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
              dynamicUser
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
            nativeStore.enable = nativeStoreEnable;
            nativeStore.stateDir = nativeStateDir;
            nativeStore.rootsDir = nativeRootsDir;
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
  evaluatesConfig = config: (builtins.tryEval config.system.build.toplevel.drvPath).success;
  gcThresholdMessage = "services.narjar.gc.targetBytes cannot exceed services.narjar.gc.maxBytes";
  gcThresholdAssertion = lib.findFirst (assertion: assertion.message == gcThresholdMessage) null (
    invalidGcThresholdConfig.assertions
  );

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
  fixedUserConfig = configuration {
    dataDir = "/var/lib/narjar";
    dynamicUser = false;
    gc = {
      enable = true;
      maxBytes = 1000;
    };
  };
  invalidGcThresholdConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      maxBytes = 1000;
      targetBytes = 2000;
    };
  };
  equalGcThresholdConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      maxBytes = 1000;
      targetBytes = 1000;
    };
  };
  lowerGcTargetConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      maxBytes = 2000;
      targetBytes = 1000;
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
  unsafeNativeRootsConfig = configuration {
    dataDir = "/var/lib/narjar";
    dynamicUser = false;
    nativeStoreEnable = true;
    nativeRootsDir = "/nix/store";
  };
  nestedNativeRootsConfig = configuration {
    dataDir = "/var/lib/narjar";
    dynamicUser = false;
    nativeStoreEnable = true;
    nativeRootsDir = "/nix/var/nix/gcroots/auto/narjar/instance/roots";
  };
  nativeStoreConfig = configuration {
    dataDir = "/var/lib/narjar";
    dynamicUser = false;
    nativeStoreEnable = true;
  };
  customNativeStateDirConfig = configuration {
    dataDir = "/var/lib/narjar";
    dynamicUser = false;
    nativeStoreEnable = true;
    nativeStateDir = "/var/lib/narjar-runtime/nix";
  };
  nativeStorePreStartCommand = lib.head (
    lib.toList nativeStoreConfig.systemd.services.narjar.serviceConfig.ExecStartPre
  );
  nativeStorePreStartScript = builtins.readFile (lib.removePrefix "+" nativeStorePreStartCommand);
  customNativeStorePreStartScript = builtins.readFile (lib.removePrefix "+" (lib.head (lib.toList customNativeStateDirConfig.systemd.services.narjar.serviceConfig.ExecStartPre)));
in
assert builtins.all evaluates valid;
assert builtins.all (dataDir: !(evaluates dataDir)) invalid;
assert !(evaluatesConfig invalidGcThresholdConfig);
assert gcThresholdAssertion != null;
assert !gcThresholdAssertion.assertion;
assert gcThresholdAssertion.message == gcThresholdMessage;
assert evaluatesConfig equalGcThresholdConfig;
assert evaluatesConfig lowerGcTargetConfig;
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
assert customRuntimeConfig.systemd.services.narjar.serviceConfig.DynamicUser;
assert customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.DynamicUser;
assert (customRuntimeConfig.systemd.services.narjar.serviceConfig.User == "narjar");
assert (customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.User == "narjar");
assert (customRuntimeConfig.systemd.services.narjar.serviceConfig.Group == "narjar");
assert (customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.Group == "narjar");
assert (customRuntimeConfig.systemd.services.narjar.serviceConfig.StateDirectory == "narjar");
assert (customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.StateDirectory == "narjar");
assert (builtins.substring 0 1 customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.ExecStartPre == "+");
assert (fixedUserConfig.systemd.services.narjar.serviceConfig.User == "narjar");
assert (fixedUserConfig.systemd.services.narjar-gc.serviceConfig.User == "narjar");
assert (fixedUserConfig.systemd.services.narjar.serviceConfig.Group == "narjar");
assert (fixedUserConfig.systemd.services.narjar-gc.serviceConfig.Group == "narjar");
assert (!(fixedUserConfig.systemd.services.narjar.serviceConfig.DynamicUser or false));
assert (!(fixedUserConfig.systemd.services.narjar-gc.serviceConfig.DynamicUser or false));
assert (!(builtins.tryEval invalidCompressionConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval missingPrivateReadTokenConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval conflictingFilesystemSamplesConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval unsafeNativeRootsConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval nestedNativeRootsConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval nativeStoreConfig.system.build.toplevel.drvPath).success);
assert (!(builtins.tryEval customNativeStateDirConfig.system.build.toplevel.drvPath).success);
assert (lib.any (assertion: assertion.message == "services.narjar.nativeStore cannot be enabled until native-store HTTP serving is implemented" && !assertion.assertion) nativeStoreConfig.assertions);
assert (lib.hasInfix "realpath -m" nativeStorePreStartScript);
assert (lib.hasInfix "ancestor=$roots_parent" nativeStorePreStartScript);
assert (lib.hasInfix "ancestor_owner" nativeStorePreStartScript);
assert (lib.hasInfix "roots ancestors must be root-owned" nativeStorePreStartScript);
assert (lib.hasInfix "/var/lib/narjar-runtime/nix/gcroots/auto" customNativeStorePreStartScript);
assert (lib.hasInfix "mkdir -m 0700" nativeStorePreStartScript);
assert (!(lib.hasInfix "install -d" nativeStorePreStartScript));
assert (!(lib.any (rule: lib.hasInfix "/nix/var/nix/gcroots/auto/narjar" rule) nativeStoreConfig.systemd.tmpfiles.rules));
"narjar module dataDir assertions passed"
