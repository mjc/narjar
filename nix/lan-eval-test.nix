{
  pkgs,
  evaluate,
  valid,
}: let
  inherit (pkgs) lib;
  configured = evaluate {
    services.narjar = {
      enable = true;
      publicUrl = "http://cache.local:8080";
      discovery = {
        enable = true;
        name = "Shared cache";
      };
      onboarding = {
        enable = true;
        diagnostics = true;
      };
      auth.trustedPublicKeys = "/run/keys/cache.pub";
    };
  };
  disabled = evaluate {};
  command = configured.systemd.services.narjar.serviceConfig.ExecStart;
in
  assert valid configured;
  assert !configured.services.avahi.enable;
  assert !configured.services.nginx.enable;
  assert builtins.elem "AF_NETLINK" configured.systemd.services.narjar.serviceConfig.RestrictAddressFamilies;
  assert lib.hasInfix "--public-url" command;
  assert lib.hasInfix "http://cache.local:8080" command;
  assert lib.hasInfix "--advertise" command;
  assert lib.hasInfix "--discovery-name" command;
  assert lib.hasInfix "--onboarding" command;
  assert lib.hasInfix "--onboarding-diagnostics" command;
  assert !disabled.services.narjar.discovery.enable;
  assert !disabled.services.narjar.onboarding.enable;
  assert builtins.all (cfg: !valid cfg) [
    (evaluate {services.narjar.discovery.enable = true;})
    (evaluate {services.narjar.onboarding.diagnostics = true;})
  ];
    pkgs.runCommand "narjar-lan-options-check" {} ''touch "$out"''
