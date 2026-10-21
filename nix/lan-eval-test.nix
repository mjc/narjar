{
  pkgs,
  evaluate,
  valid,
}: let
  inherit (pkgs) lib;
  key = "cache.example:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  configuration = extra:
    evaluate {
      imports = [
        {
          services.narjar = {
            enable = true;
            publicUrl = "http://cache.local:8080";
            proxy = {
              enable = true;
              tls = "off";
            };
            auth.trustedPublicKeyValues = [key];
            discovery.enable = true;
            onboarding.enable = true;
          };
          services.avahi.hostName = lib.mkDefault "cache";
        }
        extra
      ];
    };
  lan = configuration {};
  disabled = evaluate {};
  tls = evaluate {
    services.narjar = {
      enable = true;
      publicUrl = "https://cache.example";
      proxy.enable = true;
      discovery.enable = true;
    };
  };
  escaped = evaluate {
    services.narjar = {
      enable = true;
      publicUrl = "http://other.local:8081";
      discovery = {
        enable = true;
        name = "Cache <&\"'>";
      };
    };
    services.avahi.openFirewall = false;
    services.avahi.hostName = "other";
    services.avahi.extraServiceFiles.other = "preserved";
  };
  record = lan.services.avahi.extraServiceFiles.narjar;
  secondKey = "second.example:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
  multipleKeys = evaluate {
    services.narjar = {
      enable = true;
      publicUrl = "https://keys.example:8443";
      proxy = {
        enable = true;
        tls = "existing";
      };
      auth.trustedPublicKeyValues = [key secondKey];
      onboarding = {
        enable = true;
        diagnostics = true;
      };
    };
    services.nginx.virtualHosts."keys.example" = {
      sslCertificate = "/run/secrets/cache.crt";
      sslCertificateKey = "/run/secrets/cache.key";
    };
  };
  multipleKeysPage = multipleKeys.services.nginx.virtualHosts."keys.example".locations."= /".alias;
  privateCache = configuration {
    services.narjar = {
      privateRead = true;
      auth.readTokens = "/run/secrets/read.tokens";
    };
  };
  privatePage = privateCache.services.nginx.virtualHosts."cache.local".locations."= /".alias;
  page = lan.services.nginx.virtualHosts."cache.local".locations."= /".alias;
  localClient = evaluate (import ./client-configuration.nix {
    inherit lib;
    url = "http://cache.local:8080";
    keys = [key];
    client = lan.services.narjar.client;
    mode = "local-edge";
    leaseSeconds = 600;
  });
  directClient = evaluate (import ./client-configuration.nix {
    inherit lib;
    url = "https://cache.example";
    keys = [key];
    client = lan.services.narjar.client;
    mode = "direct";
    leaseSeconds = 600;
  });
  check = pkgs.runCommand "narjar-lan-onboarding-check" {nativeBuildInputs = [pkgs.libxml2];} ''
    xmllint --noout --nonet ${pkgs.writeText "narjar-lan.service" record}
    xmllint --noout --nonet ${pkgs.writeText "narjar-escaped.service" escaped.services.avahi.extraServiceFiles.narjar}
    grep -F 'http://cache.local:8080' ${page}
    grep -F 'cache.example:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' ${page}
    grep -F 'local-edge' ${page}
    grep -F 'extra-substituters' ${page}
    grep -F '${secondKey}' ${multipleKeysPage}
    grep -F 'https://keys.example:8443' ${multipleKeysPage}
    grep -F 'href="/metrics"' ${multipleKeysPage}
    grep -F 'href="/readyz"' ${multipleKeysPage}
    grep -F 'location = / {' ${lan.environment.etc."nginx/nginx.conf".source}
    grep -F 'direct substitution' ${privatePage}
    grep -F 'netrc' ${privatePage}
    if grep -F 'local-edge' ${privatePage}; then
      echo 'private cache offered an edge that cannot authenticate upstream' >&2
      exit 1
    fi
    if grep -E '127\.0\.0\.1|producer\.sec|/run/secrets|href="/metrics"' ${page}; then
      echo 'setup page exposed private backend details, secrets or unrequested diagnostics' >&2
      exit 1
    fi
    touch "$out"
  '';
in
  assert valid lan;
  assert valid localClient;
  assert valid directClient;
  assert valid multipleKeys;
  assert valid privateCache;
  # Keep setup-page defaults aligned with discover config's offline output.
  assert lan.services.narjar.client.priority == 30;
  assert lan.services.narjar.client.positiveTtlSeconds == 300;
  assert lan.services.narjar.client.negativeTtlSeconds == 1;
  assert localClient.services.avahi.nssmdns4;
  assert localClient.services.narjar.edge.leaseSeconds >= 2 * localClient.services.narjar.client.positiveTtlSeconds + 300;
  assert !directClient.services.narjar.enable;
  assert !directClient.services.avahi.enable;
  assert !disabled.services.avahi.enable;
  assert !disabled.services.narjar.discovery.enable;
  assert lan.services.avahi.enable && lan.services.avahi.publish.enable;
  assert lan.services.avahi.publish.addresses;
  assert !lan.services.avahi.publish.userServices;
  assert !lan.services.avahi.reflector;
  assert lib.hasInfix "<type>_http._tcp</type>" record;
  assert lib.hasInfix "<port>8080</port>" record;
  assert lib.hasInfix "nix-cache=1" record;
  assert lib.hasInfix "narjar=1" record;
  assert lib.hasInfix "url=http://cache.local:8080" record;
  assert lib.hasInfix "setup=/" record;
  assert !lib.hasInfix "127.0.0.1" record;
  assert valid tls;
  assert lib.hasInfix "<type>_https._tcp</type>" tls.services.avahi.extraServiceFiles.narjar;
  assert lib.hasInfix "<port>443</port>" tls.services.avahi.extraServiceFiles.narjar;
  assert !lib.hasInfix "setup=/" tls.services.avahi.extraServiceFiles.narjar;
  assert tls.services.narjar.proxy.tls == "acme";
  assert valid escaped;
  assert !escaped.services.avahi.openFirewall;
  assert escaped.services.avahi.extraServiceFiles.other == "preserved";
  assert lib.hasInfix "Cache &lt;&amp;&quot;&apos;&gt;" escaped.services.avahi.extraServiceFiles.narjar;
  assert lan.services.narjar.discovery.name != tls.services.narjar.discovery.name;
  assert lan.services.nginx.virtualHosts."cache.local".locations."/".proxyPass == "http://127.0.0.1:5000";
  assert builtins.all (cfg: !valid cfg) [
    (evaluate {services.narjar.discovery.enable = true;})
    (configuration {services.avahi.hostName = "different";})
    (evaluate {
      services.narjar = {
        enable = true;
        publicUrl = "http://localhost";
        discovery.enable = true;
      };
    })
    (evaluate {
      services.narjar = {
        enable = true;
        publicUrl = "https://cache.example";
        onboarding.enable = true;
        proxy.enable = true;
      };
    })
    (evaluate {
      services.narjar = {
        enable = true;
        publicUrl = "https://cache.example";
        discovery.enable = true;
      };
      services.avahi.publish.enable = false;
    })
    (evaluate {
      services.narjar = {
        enable = true;
        auth.trustedPublicKeys = "/run/secrets/public";
        auth.trustedPublicKeyValues = [key];
      };
    })
  ]; "${check}"
