{pkgs}: let
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
    shutdownGraceSeconds ? 30,
    stopTimeout ? null,
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
              shutdownGraceSeconds
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
          systemd.services.narjar.serviceConfig = lib.optionalAttrs (stopTimeout != null) {
            TimeoutStopSec = stopTimeout;
          };
        }
      ];
    }).config;

  evaluates = dataDir: let
    result = builtins.tryEval (
      (configuration {inherit dataDir;}).system.build.toplevel.drvPath
    );
  in
    result.success;
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
  unattendedConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      evictionOrder = "last-use";
      maxDeletions = 20;
      minFreeBytes = 1000;
      targetFreeBytes = 2000;
      retryAttempts = 4;
      retryDelayMillis = 250;
      randomizedDelaySeconds = 42;
    };
  };
  invalidUnattendedConfigs = map (gc: configuration {dataDir = "/var/lib/narjar"; inherit gc;}) [
    {enable = true; minFreeBytes = 1000;}
    {enable = true; targetFreeBytes = 2000;}
    {enable = true; minFreeBytes = 2000; targetFreeBytes = 1000;}
    {enable = true; minFreeBytes = 1000; targetFreeBytes = 2000; maxDeletions = null;}
    {enable = true; maxBytes = 1000; maxDeletions = 0;}
    {enable = true; maxBytes = 1000; retryAttempts = 17;}
    {enable = true; maxBytes = 1000; retryDelayMillis = 30001;}
  ];
  longShutdownConfig = configuration {
    dataDir = "/var/lib/narjar";
    shutdownGraceSeconds = 300;
  };
  overriddenStopTimeoutConfig = configuration {
    dataDir = "/var/lib/narjar";
    stopTimeout = 600;
  };
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
  ageDaysGcConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      maxAgeDays = 7;
    };
  };
  conflictingGcAgeConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      maxAgeDays = 7;
      maxAgeSeconds = 60;
    };
  };
  overflowingGcAgeConfig = configuration {
    dataDir = "/var/lib/narjar";
    gc = {
      enable = true;
      maxAgeDays = 213503982334602;
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
  customNativeStorePreStartCommand = lib.head (
    lib.toList customNativeStateDirConfig.systemd.services.narjar.serviceConfig.ExecStartPre
  );
  nativeStorePreStartScript = lib.removePrefix "+" nativeStorePreStartCommand;
  customNativeStorePreStartScript = lib.removePrefix "+" customNativeStorePreStartCommand;
  fixedUserPreStartScript = lib.removePrefix "+" fixedUserConfig.systemd.services.narjar.serviceConfig.ExecStartPre;
  # Inspect generated files only in the builder. The returned string keeps this
  # derivation's context, so the flake's writeText check builds it without IFD.
  preStartCheck =
    pkgs.runCommand "narjar-module-pre-start-check" {
      nativeBuildInputs = [pkgs.bash pkgs.gnugrep];
    } ''
      for script in ${lib.escapeShellArgs [nativeStorePreStartScript customNativeStorePreStartScript fixedUserPreStartScript]}; do
        bash -n "$script"
        grep -F -- 'set -eu' "$script"
        grep -F -- 'chown --no-dereference' "$script"
        grep -F -- 'expected a real directory' "$script"
      done
      grep -F -- 'realpath -m' ${lib.escapeShellArg nativeStorePreStartScript}
      grep -F -- 'ancestor=$roots_parent' ${lib.escapeShellArg nativeStorePreStartScript}
      grep -F -- 'ancestor_owner' ${lib.escapeShellArg nativeStorePreStartScript}
      grep -F -- 'roots ancestors must be root-owned' ${lib.escapeShellArg nativeStorePreStartScript}
      grep -F -- '/var/lib/narjar-runtime/nix/gcroots/auto' ${lib.escapeShellArg customNativeStorePreStartScript}
      grep -F -- 'mkdir -m 0700' ${lib.escapeShellArg nativeStorePreStartScript}
      if grep -F -- 'install -d' ${lib.escapeShellArg nativeStorePreStartScript}; then
        echo 'native-store roots must be checked before creation' >&2
        exit 1
      fi
      touch "$out"
    '';
in
  assert builtins.all evaluates valid;
  assert builtins.all (dataDir: !(evaluates dataDir)) invalid;
  assert !(evaluatesConfig invalidGcThresholdConfig);
  assert gcThresholdAssertion != null;
  assert !gcThresholdAssertion.assertion;
  assert gcThresholdAssertion.message == gcThresholdMessage;
  assert evaluatesConfig equalGcThresholdConfig;
  assert evaluatesConfig lowerGcTargetConfig;
  assert evaluatesConfig ageDaysGcConfig;
  assert evaluatesConfig unattendedConfig;
  assert lib.all (config: !(evaluatesConfig config)) invalidUnattendedConfigs;
  assert lib.hasInfix "--track-access" unattendedConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert !(lib.hasInfix "--track-access" defaultConfig.systemd.services.narjar.serviceConfig.ExecStart);
  assert lib.all (flag: lib.hasInfix flag unattendedConfig.systemd.services.narjar-gc.serviceConfig.ExecStart) [
    "--eviction-order last-use" "--max-deletions 20" "--min-free-bytes 1000" "--target-free-bytes 2000" "--retry-attempts 4" "--retry-delay-millis 250"
  ];
  assert unattendedConfig.systemd.timers.narjar-gc.timerConfig.RandomizedDelaySec == 42;
  assert lib.hasInfix "--delete-older-than 7d" ageDaysGcConfig.systemd.services.narjar-gc.serviceConfig.ExecStart;
  assert !(lib.hasInfix "--max-age-seconds" ageDaysGcConfig.systemd.services.narjar-gc.serviceConfig.ExecStart);
  assert !(evaluatesConfig conflictingGcAgeConfig);
  assert !(evaluatesConfig overflowingGcAgeConfig);
  assert defaultConfig.systemd.services.narjar.serviceConfig.TimeoutStopSec == 40;
  assert longShutdownConfig.systemd.services.narjar.serviceConfig.TimeoutStopSec == 310;
  assert lib.hasInfix "--shutdown-grace-seconds 300" longShutdownConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert overriddenStopTimeoutConfig.systemd.services.narjar.serviceConfig.TimeoutStopSec == 600;
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
  assert (lib.hasInfix "--online" customRuntimeConfig.systemd.services.narjar-gc.serviceConfig.ExecStart);
  assert !(customRuntimeConfig.systemd.services.narjar-gc.serviceConfig ? ExecStartPre);
  assert !(customRuntimeConfig.systemd.services.narjar-gc.serviceConfig ? ExecStopPost);
  assert !(fixedUserConfig.systemd.services.narjar-gc.serviceConfig ? ExecStartPre);
  assert !(fixedUserConfig.systemd.services.narjar-gc.serviceConfig ? ExecStopPost);
  assert (builtins.elem "narjar.service" customRuntimeConfig.systemd.services.narjar-gc.requires);
  assert (builtins.elem "narjar.service" customRuntimeConfig.systemd.services.narjar-gc.after);
  assert (defaultConfig.systemd.services.narjar.serviceConfig.Type == "notify");
  assert (defaultConfig.systemd.services.narjar.serviceConfig.NotifyAccess == "main");
  assert (builtins.elem "AF_UNIX" defaultConfig.systemd.services.narjar.serviceConfig.RestrictAddressFamilies);
  assert !(defaultConfig.services.narjar.gc.enable);
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
  assert lib.hasPrefix "+" nativeStorePreStartCommand;
  assert lib.hasPrefix "+" customNativeStorePreStartCommand;
  assert (!(lib.any (rule: lib.hasInfix "/nix/var/nix/gcroots/auto/narjar" rule) nativeStoreConfig.systemd.tmpfiles.rules)); "narjar module assertions passed; generated preStart check: ${preStartCheck}"
