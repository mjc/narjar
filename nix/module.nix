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
    lib.match "^/var/lib/[^/]+$" cfg.dataDir != null
    && !builtins.elem stateDirectory ["." ".."];
  runtimeDataDir =
    if cfg.dynamicUser
    then "/var/lib/private/${stateDirectory}"
    else cfg.dataDir;
  fixedPaths = [
    runtimeDataDir
    "${runtimeDataDir}/nar"
    "${runtimeDataDir}/nar/.tmp"
    "${runtimeDataDir}/.tmp"
    "${runtimeDataDir}/realisations"
    "${runtimeDataDir}/realisations/.tmp"
    "${runtimeDataDir}/auth"
    "${runtimeDataDir}/lock"
    "${runtimeDataDir}/.narjar-clean"
    "${runtimeDataDir}/nix-cache-info"
    "${runtimeDataDir}/trusted-public-keys"
    "${runtimeDataDir}/auth/write.tokens"
  ];
  optionalFixedPaths = [
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
      mode = "0644";
    }
  ];
  installCredentials =
    lib.concatMapStringsSep "\n" (credential: ''
      ${pkgs.coreutils}/bin/install -m ${credential.mode} \
        "$NARJAR_CREDENTIALS_DIRECTORY/${credential.name}" \
        ${lib.escapeShellArg "${runtimeDataDir}/${credential.target}"}
    '')
    credentials;
  validateFixedPaths =
    lib.concatMapStringsSep "\n" (path: ''
      test ! -L ${lib.escapeShellArg path}
    '') (fixedPaths ++ optionalFixedPaths);
  chownFixedPaths =
    lib.concatMapStringsSep "\n" (path: ''
      ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- ${lib.escapeShellArg path}
    '') fixedPaths;
  chownOptionalFixedPaths =
    lib.concatMapStringsSep "\n" (path: ''
      if [ -e ${lib.escapeShellArg path} ]; then
        ${pkgs.coreutils}/bin/chown --no-dereference narjar:narjar -- ${lib.escapeShellArg path}
      fi
    '') optionalFixedPaths;
  preStartBody = ''
    test ! -L ${lib.escapeShellArg runtimeDataDir}
    if [ ! -e ${lib.escapeShellArg "${runtimeDataDir}/nix-cache-info"} ]; then
      ${executable} init --data-dir ${lib.escapeShellArg runtimeDataDir}
    fi
    ${validateFixedPaths}
    ${lib.optionalString (cfg.auth.readTokens == null) ''
      ${pkgs.coreutils}/bin/rm -f ${lib.escapeShellArg "${runtimeDataDir}/auth/read.tokens"}
    ''}
    ${installCredentials}
  '';
  preStartScript = "set -eu\n${preStartBody}";
  privilegedPreStartScript = ''
    set -eu
    ${preStartBody}
    ${chownFixedPaths}
    ${chownOptionalFixedPaths}
  '';
  privilegedPreStart = pkgs.writeShellScript "narjar-pre-start" privilegedPreStartScript;
  serveArgs = lib.escapeShellArgs [
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
    "--min-free-bytes"
    (toString cfg.minFreeBytes)
  ];
  commonServiceConfig = {
    PrivateTmp = true;
    ProtectSystem = "strict";
    ReadWritePaths = [runtimeDataDir];
    UMask = "0077";
  };
  gcArgs = lib.escapeShellArgs (
    [
      "gc"
      "--data-dir"
      runtimeDataDir
      "--apply"
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
    };

    minFreeBytes = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 1024 * 1024 * 1024;
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
        description = "Host path loaded as the read token credential.";
      };

      writeTokens = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Host path loaded as the write token credential.";
      };

      trustedPublicKeys = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Host path loaded as the trusted public keys credential.";
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
        // {
          Environment = "NARJAR_CREDENTIALS_DIRECTORY=%d";
          DynamicUser = lib.mkIf cfg.dynamicUser true;
          User = lib.mkIf (!cfg.dynamicUser) "narjar";
          Group = lib.mkIf (!cfg.dynamicUser) "narjar";
          StateDirectory = lib.mkIf cfg.dynamicUser stateDirectory;
          StateDirectoryMode = lib.mkIf cfg.dynamicUser "0700";
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
    systemd.services.narjar-gc = lib.mkIf cfg.gc.enable {
      description = "Narjar offline garbage collection";
      after = ["network.target"];
      unitConfig.RequiresMountsFor = [cfg.dataDir];

      serviceConfig =
        commonServiceConfig
        // {
          Type = "oneshot";
          ExecStartPre = "${pkgs.systemd}/bin/systemctl stop narjar.service";
          ExecStart = "${executable} ${gcArgs}";
          ExecStopPost = "${pkgs.systemd}/bin/systemctl start narjar.service";
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
