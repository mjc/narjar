{
  config,
  lib,
  ...
}: let
  cfg = config.services.narjar;
in {
  options.services.narjar.p2p = {
    enable = lib.mkEnableOption "indexing local Nix store paths for peer sharing";

    storeDir = lib.mkOption {
      type = lib.types.str;
      default = "/nix/store";
      description = "Nix store directory to index. The scan examines the lexicographically first 100,000 names. This is the machine's Nix store.";
    };

    upstream = lib.mkOption {
      type = lib.types.str;
      default = "https://cache.nixos.org";
      description = "Upstream cache whose narinfo must match a path before it is offered. The original narinfo is kept, including its signatures.";
    };

    publishAll = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Offer paths in storeDir. The index examines only the lexicographically first 100,000 names. Paths without a matching upstream narinfo are signed with signingKeyFile. Without that key, those paths stay unoffered.";
    };

    signingKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Nix secret key for paths publishAll offers without an upstream narinfo. Loaded through a systemd credential.";
    };
  };

  config.assertions = [
    {
      assertion = !cfg.p2p.enable || cfg.enable;
      message = "services.narjar.p2p.enable requires services.narjar.enable";
    }
    {
      assertion = !cfg.p2p.publishAll || cfg.p2p.enable;
      message = "services.narjar.p2p.publishAll requires services.narjar.p2p.enable";
    }
    {
      assertion = cfg.p2p.signingKeyFile == null || cfg.p2p.enable;
      message = "services.narjar.p2p.signingKeyFile requires services.narjar.p2p.enable";
    }
    {
      assertion =
        !cfg.p2p.enable
        || builtins.match "https?://[^/?#@]+([/?#].*)?" cfg.p2p.upstream != null;
      message = "services.narjar.p2p.upstream must be an HTTP(S) URL with a host";
    }
  ];
}
