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
  tracker = evaluate {
    services.narjar = {
      enable = true;
      peerixTracker.enable = true;
    };
  };
  endpoint = evaluate {
    services.narjar = {
      enable = true;
      dynamicUser = false;
      peerixEndpoint = {
        enable = true;
        stateDir = "/var/lib/narjar-peerix";
        stallSeconds = 15;
      };
    };
  };
  defaultCommand = defaults.systemd.services.narjar.serviceConfig.ExecStart;
  trackerCommand = tracker.systemd.services.narjar.serviceConfig.ExecStart;
  enabledCommand = enabled.systemd.services.narjar.serviceConfig.ExecStart;
  publishCommand = publishAll.systemd.services.narjar.serviceConfig.ExecStart;
  signedCommand = signed.systemd.services.narjar.serviceConfig.ExecStart;
  endpointCommand = endpoint.systemd.services.narjar.serviceConfig.ExecStart;
  mesh = evaluate {
    services.narjar = {
      enable = true;
      storeMesh = {
        hosts = {
          other = "100.64.0.2";
          "peer.tail" = "[fd7a:115c:a1e0::8]:9730";
        };
        listen = "100.64.0.1:9722";
      };
    };
  };
  meshCommand = mesh.systemd.services.narjar.serviceConfig.ExecStart;
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
  assert !defaults.services.narjar.peerixTracker.enable;
  assert defaults.services.narjar.peerixTracker.upstream == "https://sophronesis.dev/peerix";
  assert !(lib.hasInfix "--peerix-tracker" defaultCommand);
  assert !defaults.services.narjar.peerixEndpoint.enable;
  assert defaults.services.narjar.peerixEndpoint.stateDir == null;
  assert defaults.services.narjar.peerixEndpoint.stallSeconds == 60;
  assert !(lib.hasInfix "--peerix-endpoint" defaultCommand);
  assert defaults.services.narjar.storeMesh.hosts == {};
  assert defaults.services.narjar.storeMesh.listen == null;
  assert !(lib.hasInfix "--store-mesh" defaultCommand);
  assert valid tracker;
  assert lib.hasInfix "--peerix-tracker" trackerCommand;
  assert lib.hasInfix "--peerix-tracker-upstream https://sophronesis.dev/peerix" trackerCommand;
  assert valid endpoint;
  assert lib.hasInfix "--peerix-endpoint" endpointCommand;
  assert lib.hasInfix "--peerix-endpoint-stall-seconds 15" endpointCommand;
  assert lib.hasInfix "--peerix-endpoint-state-dir /var/lib/narjar-peerix" endpointCommand;
  assert !(lib.hasInfix "--advertise" endpointCommand);
  assert builtins.elem "/var/lib/narjar-peerix" endpoint.systemd.services.narjar.serviceConfig.ReadWritePaths;
  assert builtins.elem "/var/lib/narjar-peerix" endpoint.systemd.services.narjar.unitConfig.RequiresMountsFor;
  assert builtins.elem "d /var/lib/narjar-peerix 0700 narjar narjar -" endpoint.systemd.tmpfiles.rules;
  assert !valid (evaluate {
    services.narjar = {
      enable = true;
      peerixEndpoint = {
        enable = true;
        stateDir = "/var/lib/narjar-peerix";
      };
    };
  });
  assert !valid (evaluate {
    services.narjar = {
      enable = true;
      peerixEndpoint.stateDir = "/var/lib/narjar-peerix";
    };
  });
  assert valid mesh;
  assert lib.hasInfix "--store-mesh-host 'other=100.64.0.2'" meshCommand;
  assert lib.hasInfix "--store-mesh-host 'peer.tail=[fd7a:115c:a1e0::8]:9730'" meshCommand;
  assert lib.hasInfix "--store-mesh-listen 100.64.0.1:9722" meshCommand;
  assert !(lib.hasInfix "trusted=true" meshCommand);
  assert mesh.nix.settings.substituters == defaults.nix.settings.substituters;
  assert !valid (evaluate {
    services.narjar = {
      enable = true;
      storeMesh.hosts."bad name" = "100.64.0.2";
    };
  });
  assert !(lib.hasInfix "--peer-share" trackerCommand);
  assert !valid (evaluate {
    services.narjar = {
      enable = true;
      peerixTracker = {
        enable = true;
        upstream = "sophronesis.dev/peerix";
      };
    };
  });
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
  assert valid (evaluate {
    services.narjar = {
      enable = true;
      p2p = {
        enable = true;
        upstream = "http://127.0.0.1:8080";
      };
    };
  });
  assert valid (evaluate {
    services.narjar = {
      enable = true;
      p2p = {
        enable = true;
        upstream = "https://[::1]/";
      };
    };
  });
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
    (evaluate {
      services.narjar = {
        enable = true;
        p2p = {
          enable = true;
          upstream = "https://";
        };
      };
    })
    (evaluate {
      services.narjar = {
        enable = true;
        p2p = {
          enable = true;
          upstream = "http://";
        };
      };
    })
  ];
  "peer share options evaluated"
