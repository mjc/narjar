{
  pkgs,
  evaluate,
  valid,
}: let
  inherit (pkgs) lib;
  defaults = evaluate {
    services.narjar.enable = true;
  };
  enabled = evaluate {
    services.narjar = {
      enable = true;
      p2p.enable = true;
    };
  };
  publishAll = evaluate {
    services.narjar = {
      enable = true;
      p2p = {
        enable = true;
        publishAll = true;
      };
    };
  };
  signed = evaluate {
    services.narjar = {
      enable = true;
      p2p = {
        enable = true;
        publishAll = true;
        signingKeyFile = "/run/secrets/narjar-peer-signing-key";
      };
    };
  };
  defaultCommand = defaults.systemd.services.narjar.serviceConfig.ExecStart;
  enabledCommand = enabled.systemd.services.narjar.serviceConfig.ExecStart;
  publishCommand = publishAll.systemd.services.narjar.serviceConfig.ExecStart;
  signedCommand = signed.systemd.services.narjar.serviceConfig.ExecStart;
in
  assert valid defaults;
  assert valid enabled;
  assert valid publishAll;
  assert valid signed;
  assert !defaults.services.narjar.p2p.enable;
  assert !defaults.services.narjar.p2p.publishAll;
  assert defaults.services.narjar.p2p.storeDir == "/nix/store";
  assert defaults.services.narjar.p2p.upstream == "https://cache.nixos.org";
  assert defaults.services.narjar.p2p.signingKeyFile == null;
  assert !(lib.hasInfix "--peer-share" defaultCommand);
  assert lib.hasInfix "--peer-share-store /nix/store" enabledCommand;
  assert lib.hasInfix "--peer-share-upstream https://cache.nixos.org" enabledCommand;
  assert !(lib.hasInfix "--peer-share-publish-all" enabledCommand);
  assert !(lib.hasInfix "trusted=true" enabledCommand);
  assert enabled.nix.settings.substituters == defaults.nix.settings.substituters;
  assert !(builtins.elem "/nix/store" enabled.systemd.services.narjar.serviceConfig.ReadWritePaths);
  assert builtins.elem "/nix/store" enabled.systemd.services.narjar.unitConfig.RequiresMountsFor;
  assert lib.hasInfix "--peer-share-publish-all" publishCommand;
  assert lib.hasInfix "--peer-share-state-dir /nix/var/nix" publishCommand;
  assert builtins.elem "/nix/var/nix" publishAll.systemd.services.narjar.unitConfig.RequiresMountsFor;
  assert lib.hasInfix "--peer-share-signing-key-file %d/peer-share-signing-key" signedCommand;
  assert builtins.elem "peer-share-signing-key:/run/secrets/narjar-peer-signing-key" signed.systemd.services.narjar.serviceConfig.LoadCredential;
  assert !(lib.any (credential: lib.hasInfix "peer-share-signing-key:" credential) publishAll.systemd.services.narjar.serviceConfig.LoadCredential);
  assert builtins.all (cfg: !valid cfg) [
    (evaluate {services.narjar.p2p.enable = true;})
    (evaluate {services.narjar.p2p.publishAll = true;})
    (evaluate {services.narjar.p2p.signingKeyFile = "/run/secrets/key";})
    (evaluate {
      services.narjar = {
        enable = true;
        p2p = {
          enable = true;
          upstream = "cache.nixos.org";
        };
      };
    })
  ];
  "peer share options evaluated"
