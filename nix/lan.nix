{
  config,
  lib,
  ...
}: let
  cfg = config.services.narjar;
in {
  options.services.narjar = {
    publicUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://cache.example";
      description = "Public cache origin for native discovery and setup instructions. The daemon validates the URL.";
    };
    discovery = {
      enable = lib.mkEnableOption "Narjar's native LAN advertisement";
      name = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Optional DNS-SD display name. The daemon validates it and handles name collisions.";
      };
    };
    onboarding = {
      enable = lib.mkEnableOption "Narjar's client setup page at /";
      diagnostics = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Include links to the existing protected diagnostics on the setup page.";
      };
    };
  };
  config.assertions = [
    {
      assertion = !(cfg.discovery.enable || cfg.onboarding.enable) || (cfg.enable && cfg.publicUrl != null);
      message = "Narjar discovery and onboarding require an enabled daemon and publicUrl";
    }
    {
      assertion = cfg.discovery.name == null || cfg.discovery.enable;
      message = "services.narjar.discovery.name requires discovery.enable";
    }
    {
      assertion = !cfg.onboarding.diagnostics || cfg.onboarding.enable;
      message = "services.narjar.onboarding.diagnostics requires onboarding.enable";
    }
  ];
}
