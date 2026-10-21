{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.narjar;
  endpoints = import ./endpoint.nix {inherit lib;};
  endpoint = endpoints.parse cfg.publicUrl;
  publicHost = lib.toLower endpoint.host;
  avahiHost = lib.toLower "${config.services.avahi.hostName}.${config.services.avahi.domainName}";
  mdnsClient = cfg.client.enable && lib.hasSuffix ".local" (lib.toLower (endpoints.parse cfg.client.url).host);
  escape = lib.escapeXML;
  page = import ./onboarding-page.nix {
    inherit lib pkgs;
    inherit (endpoint) url;
    keys = cfg.auth.trustedPublicKeyValues;
    client = cfg.client;
    diagnostics = cfg.onboarding.diagnostics;
    privateRead = cfg.privateRead;
    clientLeaseSeconds = cfg.edge.leaseSeconds;
    role =
      if cfg.edge.enable
      then "Read-through cache"
      else if cfg.nativeStore.enable
      then "Local Nix-store cache"
      else "Shared binary cache";
    leaseSeconds =
      if cfg.nativeStore.enable
      then cfg.nativeStore.minLeaseSeconds
      else if cfg.edge.enable
      then cfg.edge.leaseSeconds
      else null;
  };
in {
  options.services.narjar = {
    discovery = {
      enable = lib.mkEnableOption "LAN cache advertisement through Avahi";
      name = lib.mkOption {
        type = lib.types.addCheck (lib.types.strMatching "[^[:cntrl:]]+") (name: builtins.stringLength name <= 63);
        default = "Narjar ${lib.substring 0 32 endpoint.host} ${lib.substring 0 8 (builtins.hashString "sha256" endpoint.url)}";
        defaultText = lib.literalExpression ''"Narjar <hostname> <URL digest>"'';
        description = "DNS-SD instance name, at most 63 UTF-8 bytes. Avahi handles LAN name collisions.";
      };
    };
    onboarding = {
      enable = lib.mkEnableOption "a static cache setup page at the exact root route";
      diagnostics = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Include readiness and metrics links on the setup page. Their existing authentication remains in effect.";
      };
    };
  };
  config = lib.mkMerge [
    (lib.mkIf mdnsClient {
      services.avahi = {
        enable = lib.mkDefault true;
        nssmdns4 = lib.mkDefault true;
        nssmdns6 = lib.mkDefault config.networking.enableIPv6;
      };
      assertions = [
        {
          assertion = config.services.avahi.enable && (config.services.avahi.nssmdns4 || config.services.avahi.nssmdns6);
          message = "services.narjar.client .local URLs require Avahi name resolution";
        }
      ];
    })
    (lib.mkIf cfg.discovery.enable {
      assertions = [
        {
          assertion = cfg.enable && cfg.publicUrl != null;
          message = "services.narjar.discovery requires an enabled server and publicUrl";
        }
        {
          assertion = !(publicHost == "localhost" || lib.hasSuffix ".localhost" publicHost || lib.hasPrefix "127." publicHost || publicHost == "0.0.0.0");
          message = "services.narjar.discovery requires a reachable public hostname, not a loopback or unspecified address";
        }
        {
          assertion = !lib.hasSuffix ".local" publicHost || publicHost == avahiHost;
          message = "services.narjar.discovery publicUrl's .local hostname must match services.avahi.hostName and domainName";
        }
        {
          assertion = builtins.stringLength "url=${endpoint.url}" <= 255;
          message = "services.narjar.discovery URL must fit in one 255-byte DNS-SD TXT record";
        }
        {
          assertion = config.services.avahi.enable && config.services.avahi.publish.enable && config.services.avahi.publish.addresses;
          message = "services.narjar.discovery requires Avahi service and address publishing";
        }
      ];
      services.avahi = {
        enable = lib.mkDefault true;
        publish.enable = lib.mkDefault true;
        publish.addresses = lib.mkDefault true;
        extraServiceFiles.narjar = ''
          <?xml version="1.0" standalone="no"?>
          <!DOCTYPE service-group SYSTEM "avahi-service.dtd">
          <service-group>
            <name replace-wildcards="no">${escape cfg.discovery.name}</name>
            <service>
              <type>_${endpoint.scheme}._tcp</type>
              <domain-name>local</domain-name>
              <port>${toString endpoint.port}</port>
              <txt-record>nix-cache=1</txt-record>
              <txt-record>narjar=1</txt-record>
              <txt-record>path=/</txt-record>
              <txt-record>${escape "url=${endpoint.url}"}</txt-record>
              ${lib.optionalString cfg.onboarding.enable "<txt-record>setup=/</txt-record>"}
            </service>
          </service-group>
        '';
      };
    })
    (lib.mkIf cfg.onboarding.enable {
      assertions = [
        {
          assertion = cfg.enable && cfg.proxy.enable && cfg.publicUrl != null;
          message = "services.narjar.onboarding requires an enabled managed proxy and publicUrl";
        }
        {
          assertion = cfg.auth.trustedPublicKeyValues != [];
          message = "services.narjar.onboarding requires auth.trustedPublicKeyValues so instructions share the server trust policy";
        }
        {
          assertion = !cfg.edge.enable || cfg.edge.leaseSeconds >= 2 * cfg.client.positiveTtlSeconds + 300;
          message = "services.narjar.onboarding requires the server edge lease to cover the advertised client TTLs";
        }
        {
          assertion = !cfg.nativeStore.enable || cfg.nativeStore.minLeaseSeconds >= 2 * cfg.client.positiveTtlSeconds + 300;
          message = "services.narjar.onboarding requires the native-store lease to cover the advertised client TTLs";
        }
      ];
      services.nginx.virtualHosts.${endpoint.host}.locations."= /" = {
        alias = page;
        extraConfig = ''
          default_type text/html;
          add_header Cache-Control "no-store" always;
          add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'" always;
        '';
      };
    })
  ];
}
