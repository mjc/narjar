{
  config,
  lib,
  ...
}: let
  inherit (lib) mkOption mkEnableOption mkIf mkMerge mkDefault types;
  cfg = config.services.narjar;
  client = cfg.client;
  endpoint = import ./endpoint.nix {inherit lib;};
  originType = endpoint.type;
  inherit (endpoint.parse cfg.publicUrl) host secure port;
  loopbackParts = builtins.match "(127[.]0[.]0[.]1|[[]::1[]]):([1-9][0-9]{0,4})" cfg.listen;
  loopback = loopbackParts != null && lib.toInt (builtins.elemAt loopbackParts 1) <= 65535;
  acme = cfg.proxy.tls == "acme";
  backendPort =
    if loopbackParts == null
    then 0
    else lib.toInt (builtins.elemAt loopbackParts 1);
  proxyListeners = config.services.nginx.virtualHosts.${host}.listen;
  hasDistinctBackendPort = listener: listener.port != null && listener.port != backendPort;
  publicHost = config.services.nginx.virtualHosts.${host};
  matchesPublicEndpoint = listener: listener.port == port && listener.ssl == secure;
  isHttpChallengeListener = listener: listener.port == 80 && !listener.ssl;
  normalizedHost = value: let
    name = lib.removeSuffix "." (lib.toLower value);
  in
    if name == "localhost"
    then "127.0.0.1"
    else name;
  normalizedOrigin = url: let
    parts = builtins.match "(http|https)://([a-z0-9.-]+)(:([0-9]+))?([/?#].*)?" (lib.toLower url);
  in
    if parts == null
    then null
    else {
      scheme = builtins.elemAt parts 0;
      host = normalizedHost (builtins.elemAt parts 1);
      port =
        if builtins.elemAt parts 3 != null
        then lib.toIntBase10 (builtins.elemAt parts 3)
        else if builtins.elemAt parts 0 == "https"
        then 443
        else 80;
    };
  upstreamOrigin = normalizedOrigin cfg.edge.upstream;
  backendOrigin = {
    scheme = "http";
    host = "127.0.0.1";
    port = backendPort;
  };
  proxyOrigins = lib.concatMap (listener:
    map (name: {
      scheme =
        if listener.ssl
        then "https"
        else "http";
      host = normalizedHost name;
      port = listener.port;
    }) ([host listener.addr] ++ lib.optional (builtins.elem listener.addr ["*" "0.0.0.0"]) "127.0.0.1"))
  proxyListeners;
  localEdge = client.enable && client.mode == "local-edge";
  substituter =
    if localEdge
    then "http://${cfg.listen}"
    else client.url;
  clientUrl = "${
    if substituter == null
    then ""
    else substituter
  }?priority=${toString client.priority}";
in {
  options.services.narjar = {
    publicUrl = mkOption {
      type = types.nullOr originType;
      default = null;
      example = "https://cache.example";
      description = "Shared cache origin, without a trailing slash. Used by the managed proxy and as the default client URL. Setting it does not enable either.";
    };
    proxy = {
      enable = mkEnableOption "a streaming Nginx virtual host for publicUrl";
      tls = mkOption {
        type = types.enum ["acme" "existing" "off"];
        default = "acme";
        description = "Use NixOS ACME, certificates configured in services.nginx.virtualHosts, or explicit plain HTTP. Configure ACME contact and challenge settings separately.";
      };
      idleTimeoutSeconds = mkOption {
        type = types.ints.positive;
        default = cfg.ioTimeoutSeconds + cfg.edge.fillTimeoutSeconds;
        defaultText = lib.literalExpression "config.services.narjar.ioTimeoutSeconds + config.services.narjar.edge.fillTimeoutSeconds";
        description = "Proxy timeout between successive I/O operations, also allowing a narinfo request to wait for a complete upstream fill. This is not a total request deadline.";
      };
    };
    client = {
      enable = mkEnableOption "Nix client configuration for a shared cache";
      url = mkOption {
        type = types.nullOr originType;
        default = cfg.publicUrl;
        defaultText = lib.literalExpression "config.services.narjar.publicUrl";
        description = "Remote cache origin. Used directly or as the local edge upstream.";
      };
      mode = mkOption {
        type = types.enum ["direct" "local-edge"];
        default = "direct";
        description = "Contact the remote cache directly, or run a verifying loopback edge which turns upstream failures into cache misses.";
      };
      substituterPolicy = mkOption {
        type = types.enum ["append" "only"];
        default = "append";
        description = "Keep other substituters, or explicitly replace the list with Narjar alone.";
      };
      trustedPublicKeys = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Producer public signing keys, installed for Nix and for local-edge verification. Obtain these from the cache operator over a trusted channel.";
      };
      priority = mkOption {
        type = types.ints.unsigned;
        default = 30;
        description = "Nix substituter priority; lower values are tried first.";
      };
      fallback = mkOption {
        type = types.bool;
        default = false;
        description = "Allow Nix to build after substitution errors. A local edge requires false and turns remote failures into misses itself. Other substituters can still fail independently.";
      };
      positiveTtlSeconds = mkOption {
        type = types.ints.positive;
        default = 300;
        description = "Nix narinfo positive-cache lifetime. The edge lease must cover two such periods plus 300 seconds.";
      };
      negativeTtlSeconds = mkOption {
        type = types.ints.positive;
        default = 1;
        description = "Nix narinfo negative-cache lifetime.";
      };
    };
  };

  config = mkMerge [
    (mkIf (cfg.enable && cfg.edge.enable) {
      assertions = [
        {
          assertion = upstreamOrigin != backendOrigin;
          message = "services.narjar.edge.upstream must not point back to the loopback backend";
        }
      ];
    })
    (mkIf cfg.proxy.enable {
      assertions = [
        {
          assertion = cfg.enable && cfg.publicUrl != null;
          message = "services.narjar.proxy requires an enabled server and publicUrl";
        }
        {
          assertion = loopback;
          message = "services.narjar.proxy requires a numeric loopback listen address";
        }
        {
          assertion = secure == (cfg.proxy.tls != "off");
          message = "services.narjar.proxy.tls must agree with publicUrl's HTTP or HTTPS scheme";
        }
        {
          assertion = !cfg.edge.enable || (upstreamOrigin != null && !builtins.elem upstreamOrigin proxyOrigins);
          message = "services.narjar.edge.upstream must have a DNS or IPv4 HTTP(S) origin outside this server's backend and proxy listeners";
        }
        {
          assertion = !acme || port == 443;
          message = "services.narjar.proxy ACME mode requires the standard HTTPS port; use existing certificates for custom HTTPS ports";
        }
        {
          assertion = proxyListeners != [] && builtins.all hasDistinctBackendPort proxyListeners;
          message = "services.narjar.proxy requires explicit listener ports different from the Narjar backend; empty or implicit listeners are unsupported";
        }
        {
          assertion = builtins.any matchesPublicEndpoint proxyListeners;
          message = "services.narjar.proxy listeners must include publicUrl's port and TLS mode";
        }
        {
          assertion = !acme || (publicHost.forceSSL && builtins.any isHttpChallengeListener proxyListeners);
          message = "services.narjar.proxy ACME mode requires HTTPS redirection and an HTTP listener on port 80";
        }
        {
          assertion = secure == (publicHost.forceSSL || publicHost.onlySSL || publicHost.addSSL);
          message = "services.narjar.proxy virtual host TLS policy must agree with publicUrl";
        }
        {
          assertion = !cfg.edge.enable || cfg.proxy.idleTimeoutSeconds >= cfg.edge.fillTimeoutSeconds + cfg.ioTimeoutSeconds;
          message = "services.narjar.proxy.idleTimeoutSeconds must cover the edge fill timeout plus ioTimeoutSeconds";
        }
      ];
      services.nginx = {
        enable = true;
        virtualHosts.${host} = {
          enableACME = mkDefault acme;
          forceSSL = mkDefault acme;
          onlySSL = mkDefault (secure && !publicHost.forceSSL && !publicHost.addSSL);
          listen = mkDefault (lib.concatMap (addr:
            [
              {
                inherit addr port;
                ssl = secure;
              }
            ]
            ++ lib.optional (publicHost.forceSSL || publicHost.addSSL) {
              inherit addr;
              port = 80;
              ssl = false;
            })
          config.services.nginx.defaultListenAddresses);
          locations."/" = {
            proxyPass = "http://${cfg.listen}";
            recommendedProxySettings = false;
            extraConfig = ''
              proxy_http_version 1.1;
              proxy_set_header Host $host;
              proxy_set_header Connection "";
              proxy_request_buffering off;
              proxy_buffering off;
              proxy_cache off;
              proxy_next_upstream off;
              proxy_intercept_errors off;
              gzip off;
              client_max_body_size ${toString (lib.max cfg.maxEncodedNarBytes (1024 * 1024))};
              client_body_timeout ${toString cfg.proxy.idleTimeoutSeconds}s;
              send_timeout ${toString cfg.proxy.idleTimeoutSeconds}s;
              proxy_connect_timeout ${toString cfg.ioTimeoutSeconds}s;
              proxy_send_timeout ${toString cfg.proxy.idleTimeoutSeconds}s;
              proxy_read_timeout ${toString cfg.proxy.idleTimeoutSeconds}s;
            '';
          };
        };
      };
    })
    (mkIf client.enable {
      assertions = [
        {
          assertion = client.url != null && client.trustedPublicKeys != [];
          message = "services.narjar.client requires url and trustedPublicKeys";
        }
        {
          assertion = !cfg.edge.configureClient;
          message = "services.narjar.client and edge.configureClient are mutually exclusive";
        }
        {
          assertion = !localEdge || (loopback && cfg.enable && cfg.edge.enable && !cfg.privateRead && !client.fallback);
          message = "services.narjar.client local-edge requires a public-read loopback edge and fallback = false";
        }
        {
          assertion = !localEdge || (cfg.edge.upstream == client.url && cfg.edge.trustedPublicKeys == client.trustedPublicKeys);
          message = "services.narjar.client local-edge must share the client URL and trusted keys";
        }
        {
          assertion = !localEdge || cfg.edge.leaseSeconds >= 2 * client.positiveTtlSeconds + 300;
          message = "services.narjar.client requires edge.leaseSeconds to cover two positive TTL windows plus 300 seconds";
        }
      ];
      nix.settings = {
        substituters =
          if client.substituterPolicy == "only"
          then lib.mkForce [clientUrl]
          else lib.mkAfter [clientUrl];
        trusted-public-keys = lib.mkAfter client.trustedPublicKeys;
        fallback = client.fallback;
        narinfo-cache-positive-ttl = client.positiveTtlSeconds;
        narinfo-cache-negative-ttl = client.negativeTtlSeconds;
      };
    })
    (mkIf localEdge {
      services.narjar = {
        enable = mkDefault true;
        edge = {
          enable = mkDefault true;
          upstream = mkDefault client.url;
          trustedPublicKeys = mkDefault client.trustedPublicKeys;
        };
      };
    })
  ];
}
