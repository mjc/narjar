{
  description = "Pinned public nixpkgs roots for the narjar corpus smoke test";

  inputs = {
    nixpkgs-old.url = "github:NixOS/nixpkgs/79386e0686b21452da450490c7ac464ecf067cf1";
    nixpkgs-mid.url = "github:NixOS/nixpkgs/3633f4ab859cd646d244802286d916f107ffeda7";
    nixpkgs-new.url = "github:NixOS/nixpkgs/71adb03f126f41a5ccbd27e2bcba3a54baec61d5";
  };

  outputs = inputs:
    let
      system = "x86_64-linux";

      mkSystem = nixpkgs: generation:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ({ lib, ... }: {
              boot.isContainer = true;
              boot.loader.grub.enable = false;
              environment.etc."narjar-generation".text = "${toString generation}\n";
              environment.systemPackages = [ pkgs.hello ];
              networking.hostName = "narjar-${toString generation}";
              system.stateVersion = "25.05";
              systemd.services.narjar-corpus-provenance = {
                description = "Corpus provenance marker";
                wantedBy = [ "multi-user.target" ];
                serviceConfig.Type = "oneshot";
                script = "${lib.getExe' pkgs.coreutils "true"}";
              };
            })
          ];
        };

      mkNamed = name: nixpkgs: generation: {
        inherit name;
        value = mkSystem nixpkgs generation;
      };
    in
    {
      nixosConfigurations = builtins.listToAttrs [
        (mkNamed "generation-2213" inputs.nixpkgs-old 2213)
        (mkNamed "generation-2214" inputs.nixpkgs-old 2214)
        (mkNamed "generation-2215" inputs.nixpkgs-old 2215)
        (mkNamed "generation-2217" inputs.nixpkgs-mid 2217)
        (mkNamed "generation-2218" inputs.nixpkgs-mid 2218)
        (mkNamed "generation-2222" inputs.nixpkgs-mid 2222)
        (mkNamed "generation-2223" inputs.nixpkgs-new 2223)
        (mkNamed "generation-2224" inputs.nixpkgs-new 2224)
        (mkNamed "generation-2225" inputs.nixpkgs-new 2225)
        (mkNamed "generation-2279" inputs.nixpkgs-new 2279)
      ];
    };
}
