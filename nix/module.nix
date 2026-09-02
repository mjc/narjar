{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.narjar;
  executable = lib.getExe' cfg.package "narjar";
  stateDirectory = lib.removePrefix "/var/lib/" cfg.dataDir;
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
  installCredentials = lib.concatMapStringsSep "\n" (credential: ''
    ${pkgs.coreutils}/bin/install -m ${credential.mode} \
      "$NARJAR_CREDENTIALS_DIRECTORY/${credential.name}" \
      ${lib.escapeShellArg "${cfg.dataDir}/${credential.target}"}
  '') credentials;
  preStartScript = ''
    if [ ! -e ${lib.escapeShellArg "${cfg.dataDir}/nix-cache-info"} ]; then
      ${executable} init --data-dir ${lib.escapeShellArg cfg.dataDir}
    fi
    ${installCredentials}
  '';
  privilegedPreStartScript = ''
    ${preStartScript}
    ${pkgs.coreutils}/bin/chown -R narjar:narjar ${lib.escapeShellArg cfg.dataDir}
  '';
  privilegedPreStart = pkgs.writeShellScript "narjar-pre-start" privilegedPreStartScript;
  serveArgs = lib.escapeShellArgs [
    "serve"
    "--data-dir"
    cfg.dataDir
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
in
{
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
          lib.hasPrefix "/var/lib/" cfg.dataDir
          && stateDirectory != ""
          && !(lib.hasInfix ".." stateDirectory);
        message = "services.narjar.dataDir must be a directory below /var/lib";
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
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      preStart = lib.mkIf cfg.dynamicUser preStartScript;

      serviceConfig = {
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
        UMask = "0077";

        AmbientCapabilities = "";
        CapabilityBoundingSet = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.dataDir ];
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
  };
}
