{
  description = "Minimal NixOS systems for the narjar corpus smoke test";

  inputs = {
    nixpkgs-old.url = "github:NixOS/nixpkgs/79386e0686b21452da450490c7ac464ecf067cf1";
    nixpkgs-mid.url = "github:NixOS/nixpkgs/3633f4ab859cd646d244802286d916f107ffeda7";
    nixpkgs-new.url = "github:NixOS/nixpkgs/71adb03f126f41a5ccbd27e2bcba3a54baec61d5";
  };

  outputs = inputs:
    let
      system = "x86_64-linux";

      mkSystem = nixpkgs:
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [{
            boot.isContainer = true;
            boot.loader.grub.enable = false;
            services.desktopManager.plasma6.enable = true;
            services.displayManager.sddm.enable = true;
            services.xserver.enable = true;
            system.stateVersion = "25.05";
          }];
        };

      mkNamed = name: nixpkgs: {
        inherit name;
        value = mkSystem nixpkgs;
      };
    in
    {
      nixosConfigurations = builtins.listToAttrs [
        (mkNamed "generation-2213" inputs.nixpkgs-old)
        (mkNamed "generation-2214" inputs.nixpkgs-old)
        (mkNamed "generation-2215" inputs.nixpkgs-old)
        (mkNamed "generation-2217" inputs.nixpkgs-mid)
        (mkNamed "generation-2218" inputs.nixpkgs-mid)
        (mkNamed "generation-2222" inputs.nixpkgs-mid)
        (mkNamed "generation-2223" inputs.nixpkgs-new)
        (mkNamed "generation-2224" inputs.nixpkgs-new)
        (mkNamed "generation-2225" inputs.nixpkgs-new)
        (mkNamed "generation-2279" inputs.nixpkgs-new)
      ];
    };
}
