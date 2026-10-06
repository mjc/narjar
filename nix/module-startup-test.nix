{
  pkgs,
  package,
}: let
  lib = pkgs.lib;
  module = import ./module.nix {self.packages.${pkgs.system}.default = package;};
  startupCase = storageBackend: dynamicUser: let
    name = "${storageBackend}-${
      if dynamicUser
      then "dynamic"
      else "fixed"
    }";
    dataDir = "/var/lib/narjar";
    runtimeDataDir =
      if dynamicUser
      then "/var/lib/private/narjar"
      else dataDir;
    config =
      (import (pkgs.path + "/nixos/lib/eval-config.nix") {
        system = pkgs.system;
        modules = [
          module
          {
            services.narjar = {
              enable = true;
              inherit package dataDir storageBackend dynamicUser;
              minFreeBytes = 0;
            };
            system.stateVersion = "25.11";
          }
        ];
      }).config;
    service = config.systemd.services.narjar;
    script =
      if dynamicUser
      then pkgs.writeText "${name}-pre-start" service.preStart
      else lib.removePrefix "+" service.serviceConfig.ExecStartPre;
  in ''
    echo 'Checking ${name} startup'
    cache="$PWD/${name}"
    # Only ownership changes are stubbed: the unprivileged builder has no
    # narjar account. Initialization, type checks, and modes run unchanged.
    substitute ${script} ${name}.sh \
      --replace-fail ${lib.escapeShellArg runtimeDataDir} "$cache" \
      ${lib.optionalString (!dynamicUser) ''--replace-fail ${pkgs.coreutils}/bin/chown ${pkgs.coreutils}/bin/true''}
    bash ${name}.sh
    bash ${name}.sh
    test -f "$cache/nix-cache-info"
    ${
      if storageBackend == "chunked"
      then ''
        test -d "$cache/.narjar-chunks"
        test -d "$cache/.narjar-manifests"
      ''
      else ''
        test ! -e "$cache/.narjar-chunks"
        test ! -e "$cache/.narjar-manifests"
      ''
    }
    mv "$cache/nar" "$cache/nar-original"
    ln -s nar-original "$cache/nar"
    if bash ${name}.sh >${name}.log 2>&1; then
      echo '${name} startup accepted a symlinked payload directory' >&2
      exit 1
    fi
    grep -F 'expected a real directory' ${name}.log
  '';
in
  pkgs.runCommand "narjar-module-startup" {
    nativeBuildInputs = [pkgs.bash pkgs.coreutils pkgs.gnugrep];
  } ''
    ${lib.concatMapStringsSep "\n" (backend:
        lib.concatMapStringsSep "\n" (startupCase backend) [true false]) ["flat" "chunked"]}
    touch "$out"
  ''
