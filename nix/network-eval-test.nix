{
  pkgs,
  module,
}: let
  inherit (pkgs) lib;
  key = "cache.example:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  evaluate = extra:
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      system = pkgs.system;
      modules = [
        module
        {
          boot.loader.grub.devices = ["nodev"];
          fileSystems."/" = {
            device = "/dev/vda";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
          security.acme = {
            acceptTerms = true;
            defaults.email = "operator@example.org";
          };
        }
        extra
      ];
    }).config;
  valid = cfg: (builtins.tryEval cfg.system.build.toplevel.drvPath).success;
  server = settings:
    evaluate {
      services.narjar = {enable = true;} // settings;
    };
  disabled = evaluate {};
  tls = server {
    publicUrl = "https://cache.example";
    proxy.enable = true;
  };
  lan = server {
    publicUrl = "http://cache.example:8080";
    proxy = {
      enable = true;
      tls = "off";
    };
  };
  existingProxy = evaluate {
    services.narjar = {
      enable = true;
      publicUrl = "https://cache.example";
      proxy = {
        enable = true;
        tls = "existing";
      };
    };
    services.nginx.virtualHosts."cache.example" = {
      sslCertificate = "/run/secrets/cache.crt";
      sslCertificateKey = "/run/secrets/cache.key";
      locations."/other".return = "200 ok";
    };
    services.nginx.virtualHosts."other.example".locations."/".return = "200 ok";
  };
  client = settings:
    evaluate {
      services.narjar.client =
        {
          enable = true;
          url = "https://cache.example";
          trustedPublicKeys = [key];
        }
        // settings;
      nix.settings.substituters = ["https://other.example"];
    };
  direct = client {};
  sole = client {
    substituterPolicy = "only";
    priority = 10;
    fallback = true;
  };
  edge = client {mode = "local-edge";};
  inheritedUrl = server {
    publicUrl = "https://cache.example";
    client = {
      enable = true;
      trustedPublicKeys = [key];
    };
  };
  ipv6Backend = server {
    publicUrl = "http://cache.example";
    proxy = {
      enable = true;
      tls = "off";
    };
    listen = "[::1]:5000";
  };
  location = tls.services.nginx.virtualHosts."cache.example".locations."/";
  proxyCheck = pkgs.runCommand "narjar-shared-proxy-check" {} ''
    for config in ${tls.environment.etc."nginx/nginx.conf".source} ${lan.environment.etc."nginx/nginx.conf".source}; do
      test -s "$config"
      for directive in \
        'proxy_http_version 1.1;' \
        'proxy_request_buffering off;' \
        'proxy_buffering off;' \
        'proxy_cache off;' \
        'proxy_intercept_errors off;' \
        'proxy_read_timeout 3600s;'; do
        grep -F -- "$directive" "$config"
      done
    done
    touch "$out"
  '';
in
  assert valid disabled;
  assert !disabled.services.nginx.enable;
  assert !disabled.services.narjar.enable;
  assert valid tls;
  assert tls.services.nginx.virtualHosts."cache.example".enableACME;
  assert tls.services.nginx.virtualHosts."cache.example".onlySSL;
  assert location.proxyPass == "http://127.0.0.1:5000";
  assert lib.hasInfix "proxy_request_buffering off;" location.extraConfig;
  assert lib.hasInfix "proxy_cache off;" location.extraConfig;
  assert !lib.hasInfix "proxy_hide_header" location.extraConfig;
  assert tls.networking.firewall.allowedTCPPorts == [];
  assert valid lan;
  assert map (listener: {inherit (listener) addr port ssl;}) lan.services.nginx.virtualHosts."cache.example".listen
  == [
    {
      addr = "0.0.0.0";
      port = 8080;
      ssl = false;
    }
  ];
  assert !lan.services.nginx.virtualHosts."cache.example".enableACME;
  assert valid existingProxy;
  assert existingProxy.services.nginx.virtualHosts ? "other.example";
  assert existingProxy.services.nginx.virtualHosts."cache.example".locations ? "/other";
  assert valid direct;
  assert !direct.services.narjar.enable;
  assert !direct.services.nginx.enable;
  assert builtins.elem "https://other.example" direct.nix.settings.substituters;
  assert builtins.elem "https://cache.example?priority=30" direct.nix.settings.substituters;
  assert builtins.elem key direct.nix.settings.trusted-public-keys;
  assert valid sole;
  assert sole.nix.settings.substituters == ["https://cache.example?priority=10"];
  assert sole.nix.settings.fallback;
  assert valid edge;
  assert edge.services.narjar.enable;
  assert edge.services.narjar.edge.enable;
  assert edge.services.narjar.edge.upstream == "https://cache.example";
  assert edge.services.narjar.edge.trustedPublicKeys == [key];
  assert builtins.elem "http://127.0.0.1:5000?priority=30" edge.nix.settings.substituters;
  assert !edge.nix.settings.fallback;
  assert edge.nix.settings.narinfo-cache-positive-ttl == 300;
  assert ipv6Backend.services.nginx.virtualHosts."cache.example".locations."/".proxyPass == "http://[::1]:5000";
  assert inheritedUrl.services.narjar.client.url == inheritedUrl.services.narjar.publicUrl;
  assert builtins.all (cfg: !valid cfg) [
    (server {proxy.enable = true;})
    (server {
      publicUrl = "http://cache.example";
      proxy.enable = true;
    })
    (server {
      publicUrl = "https://cache.example";
      proxy = {
        enable = true;
        tls = "off";
      };
    })
    (server {
      publicUrl = "https://cache.example";
      proxy.enable = true;
      listen = "0.0.0.0:5000";
    })
    (client {trustedPublicKeys = [];})
    (client {
      mode = "local-edge";
      fallback = true;
    })
    (client {url = "https://cache.example:65536";})
    (client {url = "https://cache..example";})
    (client {url = "https://cache.example/path";})
    (client {url = "https://user@cache.example";})
    (client {url = "https://cache.example?priority=1";})
    (client {url = "https://cache.example/#fragment";})
    (evaluate {services.narjar.client.enable = true;})
    (evaluate {
      services.narjar = {
        listen = "0.0.0.0:5000";
        client = {
          enable = true;
          mode = "local-edge";
          url = "https://cache.example";
          trustedPublicKeys = [key];
        };
      };
    })
    (evaluate {
      services.narjar = {
        edge.leaseSeconds = 600;
        client = {
          enable = true;
          mode = "local-edge";
          url = "https://cache.example";
          trustedPublicKeys = [key];
        };
      };
    })
  ]; "${proxyCheck}"
