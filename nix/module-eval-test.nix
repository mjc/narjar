{pkgs}: let
  lib = pkgs.lib;
  package = pkgs.writeShellScriptBin "narjar" "exit 0";
  self = {packages.${pkgs.system}.default = package;};
  module = import ./module.nix {inherit self;};
  lanCheck = import ./lan-eval-test.nix {
    inherit pkgs;
    evaluate = extra:
      (import (pkgs.path + "/nixos/lib/eval-config.nix") {
        system = pkgs.system;
        modules = [module base extra];
      }).config;
    valid = evaluatesConfig;
  };
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
    trustedPublicKeys ? null,
    nativeStoreEnable ? false,
    nativeStateDir ? "/nix/var/nix",
    nativeRootsDir ? "${nativeStateDir}/gcroots/auto/narjar",
    nativeSigningKeyFile ? null,
    collectorPackages ? null,
    gc ? {},
    edge ? {},
    workers ? 8,
    maxInFlight ? 64,
    minFreeBytes ? 0,
  }:
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.system;
      modules = [
        (
          if collectorPackages == null
          then module
          else
            {
              config,
              lib,
              ...
            }:
              module {
                inherit config lib;
                pkgs = collectorPackages;
              }
        )
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
              workers
              maxInFlight
              ;
            auth.readTokens = readTokens;
            auth.trustedPublicKeys = trustedPublicKeys;
            nativeStore.enable = nativeStoreEnable;
            nativeStore.stateDir = nativeStateDir;
            nativeStore.rootsDir = nativeRootsDir;
            nativeStore.signingKeyFile = nativeSigningKeyFile;
            inherit gc;
            inherit edge;
            inherit minFreeBytes;
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
  edgeOptions = {
    enable = true;
    upstream = "https://cache.example";
    trustedPublicKeys = ["cache.example:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="];
    configureClient = true;
    leaseSeconds = 3600;
  };
  edgeConfig = configuration {
    dataDir = "/var/lib/narjar";
    edge = edgeOptions;
  };
  sharedCacheProfileConfig = configuration {
    dataDir = "/var/lib/narjar";
    minFreeBytes = 1073741824;
    edge = edgeOptions // {
      leaseSeconds = 5187600;
      clientPositiveTtlSeconds = 2592000;
      clientNegativeTtlSeconds = 1;
    };
    gc = {
      enable = true;
      schedule = "hourly";
      randomizedDelaySeconds = 300;
      evictionOrder = "last-use";
      maxBytes = 107374182400;
      targetBytes = 85899345920;
      minFreeBytes = 21474836480;
      targetFreeBytes = 32212254720;
      maxDeletions = 100;
      retryAttempts = 3;
      retryDelayMillis = 1000;
    };
  };
  disabledEdgeKeysConfig = configuration {
    dataDir = "/var/lib/narjar";
    edge.trustedPublicKeys = edgeOptions.trustedPublicKeys;
  };
  disabledEdgeKeysWithNormalTrustConfig = configuration {
    dataDir = "/var/lib/narjar";
    edge.trustedPublicKeys = edgeOptions.trustedPublicKeys;
    trustedPublicKeys = "/run/cache-signing.pub";
  };
  conflictingEdgeKeysConfig = configuration {
    dataDir = "/var/lib/narjar";
    edge = edgeOptions;
    trustedPublicKeys = "/run/cache-signing.pub";
  };
  invalidEdgeConfigs = map (edge:
    configuration {
      dataDir = "/var/lib/narjar";
      inherit edge;
    }) [
    (edgeOptions // {leaseSeconds = 599;})
    (edgeOptions // {upstream = "file:///tmp/cache";})
    (edgeOptions // {trustedPublicKeys = [];})
    (edgeOptions // {enable = false;})
  ];
  mixedSourcesConfig = configuration {
    dataDir = "/var/lib/narjar";
    dynamicUser = false;
    nativeStoreEnable = true;
    edge = edgeOptions;
  };
  compressedEdgeConfig = configuration {
    dataDir = "/var/lib/narjar";
    egressCompression = "zstd";
    edge = edgeOptions;
  };
  singleWorkerEdgeConfig = configuration {
    dataDir = "/var/lib/narjar";
    edge = edgeOptions;
    workers = 1;
  };
  singleAdmissionEdgeConfig = configuration {
    dataDir = "/var/lib/narjar";
    edge = edgeOptions;
    maxInFlight = 1;
  };
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
  invalidUnattendedConfigs = map (gc:
    configuration {
      dataDir = "/var/lib/narjar";
      inherit gc;
    }) [
    {
      enable = true;
      minFreeBytes = 1000;
    }
    {
      enable = true;
      targetFreeBytes = 2000;
    }
    {
      enable = true;
      minFreeBytes = 2000;
      targetFreeBytes = 1000;
    }
    {
      enable = true;
      minFreeBytes = 1000;
      targetFreeBytes = 2000;
      maxDeletions = null;
    }
    {
      enable = true;
      maxBytes = 1000;
      maxDeletions = 0;
    }
    {
      enable = true;
      maxBytes = 1000;
      retryAttempts = 17;
    }
    {
      enable = true;
      maxBytes = 1000;
      retryDelayMillis = 30001;
    }
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
    nativeSigningKeyFile = "/run/secrets/narjar-native-signing-key";
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
  collectorZfs = pkgs.writeShellScriptBin "zfs" ''
    set -eu
    ${pkgs.jq}/bin/jq -cn --args '$ARGS.positional' -- "$@" >> "$TEST_ZFS_LOG"
    test "$#" -eq 6
    case "$1 $2" in
      'get -H')
        test "$3" = -o && test "$4" = value
        test "$5" = mountpoint && test "$6" = "$TEST_DATASET"
        printf '%s\n' "$TEST_DATA_DIR"
        ;;
      'list -H')
        test "$3" = -r && test "$4" = -o
        test "$5" = name && test "$6" = "$TEST_DATASET"
        printf '%s\n' "$TEST_DATASET"
        ;;
      'get -Hp')
        test "$3" = -o && test "$4" = property,value
        test "$5" = "$TEST_PROPERTIES" && test "$6" = "$TEST_DATASET"
        printf '%s\t%s\n' \
          mountpoint "$TEST_DATA_DIR" \
          used "''${TEST_USED_BYTES:-123}" logicalused 456 \
          referenced 100 logicalreferenced 400 \
          usedbydataset 80 usedbysnapshots 20 usedbychildren 10 \
          usedbyrefreservation 13 available 987654 \
          compressratio 3.70x refcompressratio 4.00x \
          compression zstd-3 recordsize 131072
        ;;
      *) exit 1 ;;
    esac
  '';
  collectorFindmnt = pkgs.writeShellScriptBin "findmnt" ''
    set -eu
    ${pkgs.jq}/bin/jq -cn --args '$ARGS.positional' -- "$@" >> "$TEST_FINDMNT_LOG"
    test "$#" -eq 6
    test "$1" = --noheadings && test "$2" = --raw && test "$3" = --output
    test "$5" = --target && test "$6" = "$TEST_DATA_DIR"
    case "$4" in
      SOURCE) printf '%s\n' "$TEST_DATASET" ;;
      FSTYPE) printf '%s\n' zfs ;;
      *) exit 1 ;;
    esac
  '';
  # Keep the generated collector intact: only redirect its fixed /run output
  # into the sandbox, and observe the actual no-copy replacement operation.
  collectorMktemp = pkgs.writeShellScript "collector-mktemp" ''
    set -eu
    test "$#" -eq 1 && test "$1" = /run/narjar-zfs-stats/.sample.XXXXXX
    exec ${pkgs.coreutils}/bin/mktemp "$TEST_SAMPLE_DIR/.sample.XXXXXX"
  '';
  collectorMv = pkgs.writeShellScript "collector-mv" ''
    set -eu
    test "$#" -eq 4 && test "$1" = -fT && test "$2" = --
    test "$4" = /run/narjar-zfs-stats/sample.json
    test "''${3%/*}" = "$TEST_SAMPLE_DIR"
    test "$(${pkgs.coreutils}/bin/stat -c %a "$3")" = 644
    cmp "$TEST_SAMPLE_DIR/sample.json" "$TEST_SAMPLE_DIR/previous.json"
    ${pkgs.jq}/bin/jq -e '.schema_version == 1 and .used_bytes == 123' "$3" > /dev/null
    printf 'replace\n' >> "$TEST_REPLACEMENTS"
    exec ${pkgs.coreutils}/bin/mv -fT -- "$3" "$TEST_SAMPLE_DIR/sample.json"
  '';
  collectorCoreutils = pkgs.runCommand "narjar-collector-test-coreutils" {} ''
    mkdir -p "$out/bin"
    for executable in ${pkgs.coreutils}/bin/*; do
      name=''${executable##*/}
      case "$name" in mktemp|mv) continue ;; esac
      ln -s "$executable" "$out/bin/$name"
    done
    ln -s ${collectorMktemp} "$out/bin/mktemp"
    ln -s ${collectorMv} "$out/bin/mv"
  '';
  collectorConfig = configuration {
    dataDir = "/var/lib/narjar collector";
    statsZfsDataset = "tank/private-narjar";
    privateRead = true;
    readTokens = "/run/private-credential-marker.tokens";
    collectorPackages =
      pkgs
      // {
        zfs = collectorZfs;
        util-linux = collectorFindmnt;
        coreutils = collectorCoreutils;
      };
  };
  collectorCheck =
    pkgs.runCommand "narjar-module-zfs-collector-check" {
      nativeBuildInputs = [pkgs.jq];
    } ''
      export TEST_DATA_DIR='/var/lib/narjar collector'
      export TEST_DATASET=tank/private-narjar
      export TEST_PROPERTIES=mountpoint,used,logicalused,referenced,logicalreferenced,usedbydataset,usedbysnapshots,usedbychildren,usedbyrefreservation,available,compressratio,refcompressratio,compression,recordsize
      export TEST_SAMPLE_DIR="$TMPDIR/samples with spaces"
      export TEST_ZFS_LOG="$TMPDIR/zfs-argv.jsonl"
      export TEST_FINDMNT_LOG="$TMPDIR/findmnt-argv.jsonl"
      export TEST_REPLACEMENTS="$TMPDIR/replacements"
      mkdir -p "$TEST_SAMPLE_DIR"
      printf '%s\n' '{"previous":"complete sample"}' > "$TEST_SAMPLE_DIR/sample.json"
      cp "$TEST_SAMPLE_DIR/sample.json" "$TEST_SAMPLE_DIR/previous.json"
      started=$(date +%s)
      if ! ${collectorConfig.systemd.services.narjar-zfs-stats.serviceConfig.ExecStart} > "$TMPDIR/stdout" 2> "$TMPDIR/stderr"; then
        cat "$TMPDIR/stderr" >&2
        if test -s "$TEST_ZFS_LOG"; then cat "$TEST_ZFS_LOG" >&2; fi
        echo 'generated ZFS collector failed; expected one comma-separated property-list argument' >&2
        exit 1
      fi
      completed=$(date +%s)
      test ! -s "$TMPDIR/stdout" && test ! -s "$TMPDIR/stderr"
      jq -es --arg dataset "$TEST_DATASET" --arg properties "$TEST_PROPERTIES" '
        . == [
          ["get", "-H", "-o", "value", "mountpoint", $dataset],
          ["list", "-H", "-r", "-o", "name", $dataset],
          ["get", "-Hp", "-o", "property,value", $properties, $dataset]
        ]' "$TEST_ZFS_LOG"
      jq -es --arg root "$TEST_DATA_DIR" '
        . == [
          ["--noheadings", "--raw", "--output", "SOURCE", "--target", $root],
          ["--noheadings", "--raw", "--output", "FSTYPE", "--target", $root]
        ]' "$TEST_FINDMNT_LOG"
      jq -e --arg root "$TEST_DATA_DIR" --arg dataset "$TEST_DATASET" \
        --argjson started "$started" --argjson completed "$completed" '
        .sampled_at_unix_seconds as $time |
        ($time | type == "number") and ($time >= $started and $time <= $completed) and
        . == {
          schema_version: 1,
          storage_root: ($root | sub("^/var/lib/"; "/var/lib/private/")),
          dataset: $dataset, mountpoint: $root, sampled_at_unix_seconds: $time,
          used_bytes: 123, logical_used_bytes: 456,
          referenced_bytes: 100, logical_referenced_bytes: 400,
          used_by_dataset_bytes: 80, used_by_snapshots_bytes: 20,
          used_by_children_bytes: 10, used_by_refreservation_bytes: 13,
          available_bytes: 987654, compression_ratio: "3.70x",
          referenced_compression_ratio: "4.00x", compression: "zstd-3",
          record_size_bytes: 131072
        }' "$TEST_SAMPLE_DIR/sample.json"
      test "$(cat "$TEST_REPLACEMENTS")" = replace
      cp "$TEST_SAMPLE_DIR/sample.json" "$TEST_SAMPLE_DIR/previous.json"
      export TEST_USED_BYTES=invalid
      if ${collectorConfig.systemd.services.narjar-zfs-stats.serviceConfig.ExecStart} > "$TMPDIR/failed-stdout" 2> "$TMPDIR/failed-stderr"; then
        echo 'collector accepted malformed numeric output' >&2
        exit 1
      fi
      cmp "$TEST_SAMPLE_DIR/sample.json" "$TEST_SAMPLE_DIR/previous.json"
      test "$(cat "$TEST_REPLACEMENTS")" = replace
      test ! -s "$TMPDIR/failed-stdout"
      if grep -E '/var/lib/|tank/private-narjar|private-credential-marker' "$TMPDIR/failed-stderr"; then
        echo 'collector leaked local provenance or credentials in diagnostics' >&2
        exit 1
      fi
      if grep -F private-credential-marker "$TEST_SAMPLE_DIR/sample.json"; then
        echo 'collector leaked credentials in its sample' >&2
        exit 1
      fi
      for temporary_file in "$TEST_SAMPLE_DIR"/.sample.*; do
        if test -e "$temporary_file"; then
          echo 'collector left temporary samples behind' >&2
          exit 1
        fi
      done
      touch "$out"
    '';
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
  assert lanCheck != "";
  assert evaluatesConfig edgeConfig;
  assert evaluatesConfig disabledEdgeKeysConfig;
  assert disabledEdgeKeysConfig.systemd.services.narjar.serviceConfig.LoadCredential == defaultConfig.systemd.services.narjar.serviceConfig.LoadCredential;
  assert evaluatesConfig disabledEdgeKeysWithNormalTrustConfig;
  assert !(evaluatesConfig conflictingEdgeKeysConfig);
  assert builtins.elem "trusted-public-keys:/run/cache-signing.pub" disabledEdgeKeysWithNormalTrustConfig.systemd.services.narjar.serviceConfig.LoadCredential;
  assert lib.any (credential: lib.hasInfix "trusted-public-keys:/nix/store/" credential) edgeConfig.systemd.services.narjar.serviceConfig.LoadCredential;
  assert lib.all (config: !(evaluatesConfig config)) invalidEdgeConfigs;
  assert !(evaluatesConfig mixedSourcesConfig);
  assert !(evaluatesConfig compressedEdgeConfig);
  assert lib.hasInfix "--serve-source read-through" edgeConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert lib.hasInfix "--edge-upstream https://cache.example" edgeConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert lib.hasInfix "--edge-lease-seconds 3600" edgeConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert lib.hasInfix "--edge-fill-timeout-seconds 3600" edgeConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert evaluatesConfig sharedCacheProfileConfig;
  assert lib.hasInfix "--min-free-bytes 1073741824" sharedCacheProfileConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert lib.hasInfix "--edge-lease-seconds 5187600" sharedCacheProfileConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert sharedCacheProfileConfig.nix.settings.narinfo-cache-positive-ttl == 2592000;
  assert sharedCacheProfileConfig.nix.settings.narinfo-cache-negative-ttl == 1;
  assert lib.all (flag: lib.hasInfix flag sharedCacheProfileConfig.systemd.services.narjar-gc.serviceConfig.ExecStart) [
    "--eviction-order last-use"
    "--max-bytes 107374182400"
    "--target-bytes 85899345920"
    "--min-free-bytes 21474836480"
    "--target-free-bytes 32212254720"
    "--max-deletions 100"
    "--retry-attempts 3"
    "--retry-delay-millis 1000"
  ];
  assert lib.hasInfix "--track-access" sharedCacheProfileConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert sharedCacheProfileConfig.systemd.timers.narjar-gc.timerConfig.OnCalendar == "hourly";
  assert !(evaluatesConfig singleWorkerEdgeConfig);
  assert !(evaluatesConfig singleAdmissionEdgeConfig);
  assert edgeConfig.nix.settings.substituters == ["http://127.0.0.1:5000"];
  assert edgeConfig.nix.settings.fallback == false;
  assert edgeConfig.nix.settings.narinfo-cache-positive-ttl == 300;
  assert edgeConfig.nix.settings.narinfo-cache-negative-ttl == 1;
  assert lib.all (key: builtins.elem key edgeConfig.nix.settings.trusted-public-keys) edgeOptions.trustedPublicKeys;
  assert !(lib.hasInfix "--edge-upstream" defaultConfig.systemd.services.narjar.serviceConfig.ExecStart);
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
    "--eviction-order last-use"
    "--max-deletions 20"
    "--min-free-bytes 1000"
    "--target-free-bytes 2000"
    "--retry-attempts 4"
    "--retry-delay-millis 250"
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
  assert (builtins.tryEval nativeStoreConfig.system.build.toplevel.drvPath).success;
  assert (builtins.tryEval customNativeStateDirConfig.system.build.toplevel.drvPath).success;
  assert lib.hasInfix "--native-signing-key-file" nativeStoreConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert lib.hasInfix "%d/native-signing-key" nativeStoreConfig.systemd.services.narjar.serviceConfig.ExecStart;
  assert builtins.elem "native-signing-key:/run/secrets/narjar-native-signing-key" nativeStoreConfig.systemd.services.narjar.serviceConfig.LoadCredential;
  assert nativeStoreConfig.services.narjar.nativeStore.minLeaseSeconds >= 2 * 2592000 + 3600;
  assert !(builtins.elem "/nix/store" nativeStoreConfig.systemd.services.narjar.serviceConfig.ReadWritePaths);
  assert !(builtins.elem "/nix/var/nix/db" nativeStoreConfig.systemd.services.narjar.serviceConfig.ReadWritePaths);
  assert lib.hasPrefix "+" nativeStorePreStartCommand;
  assert lib.hasPrefix "+" customNativeStorePreStartCommand;
  assert (!(lib.any (rule: lib.hasInfix "/nix/var/nix/gcroots/auto/narjar" rule) nativeStoreConfig.systemd.tmpfiles.rules)); "narjar module assertions passed; generated preStart check: ${preStartCheck}; generated collector check: ${collectorCheck}; native LAN options check: ${lanCheck}"
