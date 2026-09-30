{self}: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.narjar;
  executable = lib.getExe' cfg.package "narjar";
  stateDirectory = lib.removePrefix "/var/lib/" cfg.dataDir;
  canonicalDataDir =
    lib.match "^/var/lib/[^/]+$" cfg.dataDir
    != null
    && !builtins.elem stateDirectory ["." ".."];
  runtimeDataDir =
    if cfg.dynamicUser
    then "/var/lib/private/${stateDirectory}"
    else cfg.dataDir;
  zfsSampleDirectory = "/run/narjar-zfs-stats";
  zfsSampleFile = "${zfsSampleDirectory}/sample.json";
  filesystemSampleFile =
    if cfg.statsFilesystemSample != null
    then cfg.statsFilesystemSample
    else if cfg.statsZfsDataset != null
    then zfsSampleFile
    else null;
  fixedDirectories = [
    "${runtimeDataDir}/nar"
    "${runtimeDataDir}/nar/.tmp"
    "${runtimeDataDir}/.tmp"
    "${runtimeDataDir}/.narjar-transactions"
    "${runtimeDataDir}/realisations"
    "${runtimeDataDir}/realisations/.tmp"
    "${runtimeDataDir}/auth"
    "${runtimeDataDir}/.narjar-validation"
    "${runtimeDataDir}/.narjar-ingress"
    "${runtimeDataDir}/.narjar-egress"
    "${runtimeDataDir}/.narjar-chunks"
    "${runtimeDataDir}/.narjar-manifests"
  ];
  fixedFiles = [
    "${runtimeDataDir}/lock"
    "${runtimeDataDir}/.narjar-layout"
    "${runtimeDataDir}/nix-cache-info"
    "${runtimeDataDir}/trusted-public-keys"
    "${runtimeDataDir}/auth/write.tokens"
  ];
  optionalFixedFiles = [
    "${runtimeDataDir}/.narjar-clean"
    "${runtimeDataDir}/.narjar-recovery"
    "${runtimeDataDir}/auth/read.tokens"
  ];
  credentials = lib.filter (credential: credential.source != null) [
    {
      name = "read.tokens";
      source = cfg.auth.readTokens;
      target = "auth/read.tokens";
      mode = "0600";
    }
    {
      name = "write.tokens";
      source = cfg.auth.writeTokens;
      target = "auth/write.tokens";
      mode = "0600";
    }
    {
      name = "trusted-public-keys";
      source = cfg.auth.trustedPublicKeys;
      target = "trusted-public-keys";
      mode = "0600";
    }
  ];
  credentialOwner = lib.optionalString (!cfg.dynamicUser) ''
    ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- "$credential_tmp"
  '';
  installCredentials = lib.optionalString (credentials != []) ''
    credential_tmp=
    cleanup_credential_tmp() {
      if [ -n "$credential_tmp" ]; then
        ${pkgs.coreutils}/bin/rm -f -- "$credential_tmp"
      fi
    }
    trap cleanup_credential_tmp EXIT
    install_credential() {
      local source="$1" target="$2" mode="$3" directory
      directory=''${target%/*}
      credential_tmp=$(${pkgs.coreutils}/bin/mktemp "$directory/.narjar-credential.XXXXXX")
      ${pkgs.coreutils}/bin/install -m "$mode" -- "$source" "$credential_tmp"
      ${credentialOwner}
      ${pkgs.coreutils}/bin/sync -d "$credential_tmp"
      ${pkgs.coreutils}/bin/mv -fT -- "$credential_tmp" "$target"
      credential_tmp=
      ${pkgs.coreutils}/bin/sync "$directory"
    }
    ${lib.concatMapStringsSep "\n" (credential: ''
        install_credential \
          "$NARJAR_CREDENTIALS_DIRECTORY/${credential.name}" \
          ${lib.escapeShellArg "${runtimeDataDir}/${credential.target}"} \
          ${lib.escapeShellArg credential.mode}
      '')
      credentials}
  '';
  failIfFixedPathHasWrongType = path: testOperator: expectedType: ''
    if [ -L ${lib.escapeShellArg path} ] || [ ! -${testOperator} ${lib.escapeShellArg path} ]; then
      ${pkgs.coreutils}/bin/printf '%s\n' ${lib.escapeShellArg "narjar: expected a real ${expectedType} at ${path}"} >&2
      exit 1
    fi
  '';
  # Lock every path component before a privileged chmod/chown can follow it.
  secureRuntimeDataDirectory = ''
    if [ -L ${lib.escapeShellArg runtimeDataDir} ] || { [ -e ${lib.escapeShellArg runtimeDataDir} ] && [ ! -d ${lib.escapeShellArg runtimeDataDir} ]; }; then
      ${pkgs.coreutils}/bin/printf '%s\n' ${lib.escapeShellArg "narjar: expected a real directory at ${runtimeDataDir}"} >&2
      exit 1
    fi
    ${pkgs.coreutils}/bin/mkdir -p -m 0700 -- ${lib.escapeShellArg runtimeDataDir}
    ${pkgs.coreutils}/bin/chown --no-dereference root:root -- ${lib.escapeShellArg runtimeDataDir}
    ${pkgs.coreutils}/bin/chmod --no-dereference 0700 -- ${lib.escapeShellArg runtimeDataDir}
  '';
  lockFixedDirectories =
    lib.concatMapStringsSep "\n" (path: ''
      ${failIfFixedPathHasWrongType path "d" "directory"}
      ${pkgs.coreutils}/bin/chmod --no-dereference 0700 -- ${lib.escapeShellArg path}
      ${pkgs.coreutils}/bin/chown --no-dereference root:root -- ${lib.escapeShellArg path}
    '')
    fixedDirectories;
  validateFixedDirectories = lib.concatMapStringsSep "\n" (path: failIfFixedPathHasWrongType path "d" "directory") fixedDirectories;
  managedCredentialPaths = map (credential: "${runtimeDataDir}/${credential.target}") credentials;
  unmanagedFixedFiles = lib.filter (path: !(builtins.elem path managedCredentialPaths)) fixedFiles;
  validateUnmanagedFixedFiles = lib.concatMapStringsSep "\n" (path: failIfFixedPathHasWrongType path "f" "regular file") unmanagedFixedFiles;
  validateManagedCredentialTargets =
    lib.concatMapStringsSep "\n" (path: ''
      if [ -L ${lib.escapeShellArg path} ] || { [ -e ${lib.escapeShellArg path} ] && [ ! -f ${lib.escapeShellArg path} ]; }; then
        ${pkgs.coreutils}/bin/printf '%s\n' ${lib.escapeShellArg "narjar: expected a regular managed credential file at ${path}"} >&2
        exit 1
      fi
    '')
    managedCredentialPaths;
  validateOptionalFixedFiles =
    lib.concatMapStringsSep "\n" (path: ''
      if [ -L ${lib.escapeShellArg path} ] || { [ -e ${lib.escapeShellArg path} ] && [ ! -f ${lib.escapeShellArg path} ]; }; then
        ${pkgs.coreutils}/bin/printf '%s\n' ${lib.escapeShellArg "narjar: expected an optional regular file at ${path}"} >&2
        exit 1
      fi
    '')
    optionalFixedFiles;
  validateFilesBeforeCredentialInstall = "${validateUnmanagedFixedFiles}\n${validateManagedCredentialTargets}\n${validateOptionalFixedFiles}";
  validateFilesAfterCredentialInstall = "${lib.concatMapStringsSep "\n" (path: failIfFixedPathHasWrongType path "f" "regular file") fixedFiles}\n${validateOptionalFixedFiles}";
  validateFixedPaths = "${validateFixedDirectories}\n${validateFilesBeforeCredentialInstall}";
  chownFixedFiles =
    lib.concatMapStringsSep "\n" (path: ''
      ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- ${lib.escapeShellArg path}
    '')
    fixedFiles;
  restoreFixedDirectories = lib.concatMapStringsSep "\n" (path: ''
    ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- ${lib.escapeShellArg path}
  '') (lib.reverseList fixedDirectories);
  chownOptionalFixedPaths =
    lib.concatMapStringsSep "\n" (path: ''
      if [ -e ${lib.escapeShellArg path} ]; then
        ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- ${lib.escapeShellArg path}
      fi
    '')
    optionalFixedFiles;
  setFixedFileModes =
    lib.concatMapStringsSep "\n" (path: ''
      ${pkgs.coreutils}/bin/chmod --no-dereference 0600 -- ${lib.escapeShellArg path}
    '')
    fixedFiles;
  setOptionalFixedFileModes =
    lib.concatMapStringsSep "\n" (path: ''
      if [ -e ${lib.escapeShellArg path} ]; then
        ${pkgs.coreutils}/bin/chmod --no-dereference 0600 -- ${lib.escapeShellArg path}
      fi
    '')
    optionalFixedFiles;
  initializeIfNeeded = ''
    test ! -L ${lib.escapeShellArg runtimeDataDir}
    if [ ! -e ${lib.escapeShellArg "${runtimeDataDir}/nix-cache-info"} ]; then
      ${executable} ${initArgs}
    fi
  '';
  prepareCredentials = ''
    ${lib.optionalString (cfg.auth.readTokens == null) ''
      if [ -e ${lib.escapeShellArg "${runtimeDataDir}/auth/read.tokens"} ]; then
        ${pkgs.coreutils}/bin/rm -f -- ${lib.escapeShellArg "${runtimeDataDir}/auth/read.tokens"}
        ${pkgs.coreutils}/bin/sync ${lib.escapeShellArg "${runtimeDataDir}/auth"}
      fi
    ''}
    ${installCredentials}
  '';
  preStartScript = "set -eu\n${initializeIfNeeded}\n${validateFixedPaths}\n${prepareCredentials}\n${validateFilesAfterCredentialInstall}";
  privilegedPreStartScript = ''
    set -eu
    ${secureRuntimeDataDirectory}
    ${initializeIfNeeded}
    ${lockFixedDirectories}
    ${validateFilesBeforeCredentialInstall}
    ${prepareCredentials}
    ${validateFilesAfterCredentialInstall}
    ${chownFixedFiles}
    ${chownOptionalFixedPaths}
    ${setFixedFileModes}
    ${setOptionalFixedFileModes}
    ${restoreFixedDirectories}
    ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- ${lib.escapeShellArg runtimeDataDir}
  '';
  privilegedPreStart = pkgs.writeShellScript "narjar-pre-start" privilegedPreStartScript;
  initArgs = lib.escapeShellArgs (
    [
      "init"
      "--data-dir"
      runtimeDataDir
      "--priority"
      (toString cfg.cachePriority)
      "--storage-backend"
      cfg.storageBackend
    ]
    ++ lib.optionals cfg.privateRead ["--private-read"]
  );
  serveArgs = lib.escapeShellArgs (
    [
      "serve"
      "--data-dir"
      runtimeDataDir
      "--listen"
      cfg.listen
      "--workers"
      (toString cfg.workers)
      "--max-in-flight"
      (toString cfg.maxInFlight)
      "--max-nar-bytes"
      (toString cfg.maxNarBytes)
      "--max-encoded-nar-bytes"
      (toString cfg.maxEncodedNarBytes)
      "--max-decoder-memory-bytes"
      (toString cfg.maxDecoderMemoryBytes)
      "--min-free-bytes"
      (toString cfg.minFreeBytes)
      "--shutdown-grace-seconds"
      (toString cfg.shutdownGraceSeconds)
      "--io-timeout-seconds"
      (toString cfg.ioTimeoutSeconds)
      "--egress-compression"
      cfg.egressCompression
      "--storage-backend"
      cfg.storageBackend
    ]
      ++ lib.optionals cfg.statsInventory [
        "--stats-inventory-interval-seconds"
        (toString cfg.statsInventoryIntervalSeconds)
      ]
      ++ lib.optionals (filesystemSampleFile != null) [
        "--stats-filesystem-sample"
        filesystemSampleFile
      ]
  );
  zfsProperties = [
    "mountpoint"
    "used"
    "logicalused"
    "referenced"
    "logicalreferenced"
    "usedbydataset"
    "usedbysnapshots"
    "usedbychildren"
    "usedbyrefreservation"
    "available"
    "compressratio"
    "refcompressratio"
    "compression"
    "recordsize"
  ];
  zfsSampleCollector = lib.optionalString (cfg.statsZfsDataset != null) (pkgs.writeShellScript "narjar-zfs-stats-sample" ''
    set -eu
    dataset=${lib.escapeShellArg (if cfg.statsZfsDataset == null then "" else cfg.statsZfsDataset)}
    expected_mountpoint=${lib.escapeShellArg cfg.dataDir}
    storage_root=${lib.escapeShellArg runtimeDataDir}
    sample_directory=${lib.escapeShellArg zfsSampleDirectory}
    temporary_file=

    cleanup() {
      if [ -n "$temporary_file" ]; then
        ${pkgs.coreutils}/bin/rm -f -- "$temporary_file"
      fi
    }
    trap cleanup EXIT

    actual_mountpoint=$(${pkgs.zfs}/bin/zfs get -H -o value mountpoint "$dataset")
    test "$actual_mountpoint" = "$expected_mountpoint"
    mounted_source=$(${pkgs.util-linux}/bin/findmnt --noheadings --raw --output SOURCE --target "$expected_mountpoint")
    mounted_type=$(${pkgs.util-linux}/bin/findmnt --noheadings --raw --output FSTYPE --target "$expected_mountpoint")
    test "$mounted_source" = "$dataset"
    test "$mounted_type" = "zfs"
    descendant_count=$(${pkgs.zfs}/bin/zfs list -H -r -o name "$dataset" | ${pkgs.coreutils}/bin/wc -l)
    test "$descendant_count" -eq 1

    properties=$(${pkgs.zfs}/bin/zfs get -Hp -o property,value ${lib.escapeShellArgs zfsProperties} "$dataset")
    temporary_file=$(${pkgs.coreutils}/bin/mktemp "$sample_directory/.sample.XXXXXX")
    printf '%s\n' "$properties" | ${pkgs.jq}/bin/jq -Rn \
      --arg storage_root "$storage_root" \
      --arg dataset "$dataset" '
        [inputs | split("\t") | {(.[0]): .[1]}] | add | . as $p |
        {
          schema_version: 1,
          storage_root: $storage_root,
          dataset: $dataset,
          mountpoint: $p.mountpoint,
          sampled_at_unix_seconds: (now | floor),
          used_bytes: ($p.used | tonumber),
          logical_used_bytes: ($p.logicalused | tonumber),
          referenced_bytes: ($p.referenced | tonumber),
          logical_referenced_bytes: ($p.logicalreferenced | tonumber),
          used_by_dataset_bytes: ($p.usedbydataset | tonumber),
          used_by_snapshots_bytes: ($p.usedbysnapshots | tonumber),
          used_by_children_bytes: ($p.usedbychildren | tonumber),
          used_by_refreservation_bytes: ($p.usedbyrefreservation | tonumber),
          available_bytes: ($p.available | tonumber),
          compression_ratio: $p.compressratio,
          referenced_compression_ratio: $p.refcompressratio,
          compression: $p.compression,
          record_size_bytes: ($p.recordsize | tonumber)
        }
      ' > "$temporary_file"
    ${pkgs.coreutils}/bin/chmod 0644 "$temporary_file"
    ${pkgs.coreutils}/bin/mv -fT -- "$temporary_file" ${lib.escapeShellArg zfsSampleFile}
    temporary_file=
  '');
  commonServiceConfig = {
    PrivateTmp = true;
    ProtectSystem = "strict";
    ReadWritePaths = [runtimeDataDir];
    UMask = "0077";
  };
  serviceIdentityConfig =
    if cfg.dynamicUser
    then {
      DynamicUser = true;
      User = "narjar";
      Group = "narjar";
      StateDirectory = stateDirectory;
      StateDirectoryMode = "0700";
    }
    else {
      User = "narjar";
      Group = "narjar";
    };
  gcArgs = lib.escapeShellArgs (
    [
      "gc"
      "--data-dir"
      runtimeDataDir
      "--apply"
      "--storage-backend"
      cfg.storageBackend
    ]
    ++ lib.optionals (cfg.gc.maxBytes != null) [
      "--max-bytes"
      (toString cfg.gc.maxBytes)
    ]
    ++ lib.optionals (cfg.gc.targetBytes != null) [
      "--target-bytes"
      (toString cfg.gc.targetBytes)
    ]
    ++ lib.optionals (cfg.gc.maxAgeSeconds != null) [
      "--max-age-seconds"
      (toString cfg.gc.maxAgeSeconds)
    ]
    ++ lib.optionals (cfg.gc.minAgeSeconds != 0) [
      "--min-age-seconds"
      (toString cfg.gc.minAgeSeconds)
    ]
    ++ lib.optionals (cfg.gc.protectedRoots != null) [
      "--protected-roots"
      cfg.gc.protectedRoots
    ]
  );
in {
  options.services.narjar = {
    enable = lib.mkEnableOption "the Narjar binary cache";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "self.packages.${pkgs.stdenv.hostPlatform.system}.default";
      description = "Narjar package to run.";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/narjar";
      description = "State directory below /var/lib.";
    };

    dynamicUser = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Run with a transient user and systemd-managed state storage.";
    };

    cachePriority = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 30;
      description = "Nix binary-cache priority written during first-run initialization.";
    };

    privateRead = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Require read credentials by initializing the cache with private reads.";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:5000";
      description = "TCP address passed to narjar serve.";
    };

    workers = lib.mkOption {
      type = lib.types.ints.positive;
      default = 8;
    };

    maxInFlight = lib.mkOption {
      type = lib.types.ints.positive;
      default = 64;
    };

    maxNarBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 16 * 1024 * 1024 * 1024;
      description = "Maximum decoded NAR size.";
    };

    maxEncodedNarBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 16 * 1024 * 1024 * 1024;
      description = "Maximum encoded NAR upload size.";
    };

    maxDecoderMemoryBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 128 * 1024 * 1024;
      description = "Maximum decoder working memory per compressed upload.";
    };

    minFreeBytes = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 1024 * 1024 * 1024;
    };

    shutdownGraceSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
    };

    ioTimeoutSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = "Per-connection I/O timeout passed to narjar serve.";
    };

    egressCompression = lib.mkOption {
      type = lib.types.enum ["none" "zstd" "xz"];
      default = "none";
      description = "NAR representation advertised to Nix clients.";
    };

    storageBackend = lib.mkOption {
      type = lib.types.enum ["flat" "chunked"];
      default = "flat";
      description = "Payload storage layout used by initialization, serving, and maintenance.";
    };

    statsInventory = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the delayed, bounded cache-population sampler.";
    };

    statsInventoryIntervalSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 900;
      description = "Interval between cache-population scans when statsInventory is enabled.";
    };

    statsZfsDataset = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional ZFS dataset mounted directly at dataDir; enables a bounded one-minute read-only usage sample.";
    };

    statsFilesystemSample = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional externally maintained filesystem sample JSON file passed to narjar serve.";
    };

    gc = {
      enable = lib.mkEnableOption "scheduled Narjar garbage collection";

      schedule = lib.mkOption {
        type = lib.types.str;
        default = "weekly";
        description = "systemd OnCalendar expression for offline garbage collection.";
      };

      maxBytes = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.unsigned;
        default = null;
        description = "Maximum cache bytes before collection is needed.";
      };

      targetBytes = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.unsigned;
        default = null;
        description = "Target cache bytes for collection.";
      };

      maxAgeSeconds = lib.mkOption {
        type = lib.types.nullOr lib.types.ints.unsigned;
        default = null;
        description = "Maximum publication age in seconds.";
      };

      minAgeSeconds = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 0;
        description = "Minimum publication age in seconds.";
      };

      protectedRoots = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "File containing protected store paths or hashes.";
      };
    };

    auth = {
      readTokens = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Host path loaded as the read token credential; null removes the managed read-token file.";
      };

      writeTokens = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Host path loaded as the write token credential; null preserves the operator-managed file.";
      };

      trustedPublicKeys = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Host path loaded as the trusted public keys credential; null preserves the operator-managed file.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          canonicalDataDir;
        message = "services.narjar.dataDir must be one canonical directory below /var/lib, such as /var/lib/narjar";
      }
      {
        assertion =
          !cfg.gc.enable
          || cfg.gc.maxBytes != null
          || cfg.gc.targetBytes != null
          || cfg.gc.maxAgeSeconds != null;
        message = "services.narjar.gc requires maxBytes, targetBytes, or maxAgeSeconds";
      }
      {
        assertion = cfg.statsZfsDataset == null || cfg.statsZfsDataset != "";
        message = "services.narjar.statsZfsDataset must be null or a non-empty ZFS dataset name";
      }
      {
        assertion = cfg.statsFilesystemSample == null || cfg.statsZfsDataset == null;
        message = "services.narjar.statsFilesystemSample and statsZfsDataset are mutually exclusive";
      }
      {
        assertion = !cfg.privateRead || cfg.auth.readTokens != null;
        message = "services.narjar.privateRead requires services.narjar.auth.readTokens";
      }
    ];

    users.groups.narjar = lib.mkIf (!cfg.dynamicUser) {};
    users.users.narjar = lib.mkIf (!cfg.dynamicUser) {
      isSystemUser = true;
      group = "narjar";
    };
    systemd.tmpfiles.rules = lib.optional (!cfg.dynamicUser) "d ${cfg.dataDir} 0700 narjar narjar -";

    systemd.services.narjar = {
      description = "Narjar binary cache";
      wantedBy = ["multi-user.target"];
      after = ["network.target"];
      unitConfig.RequiresMountsFor = [cfg.dataDir];

      preStart = lib.mkIf cfg.dynamicUser preStartScript;

      serviceConfig =
        commonServiceConfig
        // serviceIdentityConfig
        // {
          Environment = "NARJAR_CREDENTIALS_DIRECTORY=%d";
          ExecStartPre = lib.mkIf (!cfg.dynamicUser) "+${privilegedPreStart}";
          LoadCredential = map (credential: "${credential.name}:${credential.source}") credentials;
          ExecStart = "${executable} ${serveArgs}";
          Restart = "on-failure";

          AmbientCapabilities = "";
          CapabilityBoundingSet = "";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          RemoveIPC = true;
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
          ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "~@resources"
          ];
        };
    };
    systemd.services.narjar-zfs-stats = lib.mkIf (cfg.statsZfsDataset != null) {
      description = "Sample Narjar ZFS dataset usage";
      after = ["local-fs.target" "zfs-import.target"];
      unitConfig.RequiresMountsFor = [cfg.dataDir];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = zfsSampleCollector;
        TimeoutStartSec = "15s";
        RuntimeDirectory = "narjar-zfs-stats";
        RuntimeDirectoryMode = "0755";
        RuntimeDirectoryPreserve = "yes";
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
        DevicePolicy = "closed";
        DeviceAllow = ["/dev/zfs rw"];
        ReadWritePaths = [zfsSampleDirectory];
        RestrictAddressFamilies = [ ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
      };
    };

    systemd.timers.narjar-zfs-stats = lib.mkIf (cfg.statsZfsDataset != null) {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnBootSec = "60s";
        OnUnitActiveSec = "60s";
        Unit = "narjar-zfs-stats.service";
      };
    };
    systemd.services.narjar-gc = lib.mkIf cfg.gc.enable {
      description = "Narjar offline garbage collection";
      after = ["network.target"];
      unitConfig.RequiresMountsFor = [cfg.dataDir];

      serviceConfig =
        commonServiceConfig
        // serviceIdentityConfig
        // {
          Type = "oneshot";
          ExecStartPre = "+${pkgs.systemd}/bin/systemctl stop narjar.service";
          ExecStart = "${executable} ${gcArgs}";
          ExecStopPost = "+${pkgs.systemd}/bin/systemctl start narjar.service";
          TimeoutStartSec = "infinity";
        };
    };

    systemd.timers.narjar-gc = lib.mkIf cfg.gc.enable {
      wantedBy = ["timers.target"];
      timerConfig = {
        OnCalendar = cfg.gc.schedule;
        Persistent = true;
        Unit = "narjar-gc.service";
      };
    };
  };
}
