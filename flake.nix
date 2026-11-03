{
  description = "Rekey and generate sops secrets for NixOS hosts (agenix-rekey for sops-nix)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      sops-nix,
    }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkApp = args: import ./nix/app.nix ({ inherit lib; } // args);

      testHosts = import ./tests/hosts.nix;
      testNodes = lib.mapAttrs (
        _: module:
        lib.nixosSystem {
          system = "x86_64-linux";
          modules = [
            sops-nix.nixosModules.sops
            self.nixosModules.default
            module
            {
              boot.loader.grub.enable = false;
              fileSystems."/".device = "/dev/null";
              system.stateVersion = "25.11";
            }
          ];
        }
      ) testHosts;
      testApp =
        pkgs:
        mkApp {
          inherit pkgs;
          nodes = testNodes;
          masterRecipients.age = [ (lib.trim (builtins.readFile ./tests/fixtures/master.pub)) ];
          masterIdentities = [ ./tests/fixtures/master.key ];
        };
    in
    {
      nixosModules.default = ./nix/module.nix;
      flakeModules.default = ./nix/flake-module.nix;
      flakeModule = self.flakeModules.default;

      overlays.default = final: _: { sops-rekey = final.callPackage ./nix/package.nix { }; };

      lib = {
        inherit mkApp;

        configure =
          {
            nodes,
            masterRecipients ? { },
            masterIdentities ? [ ],
            agePlugins ? (_: [ ]),
            pkgsFor ? system: nixpkgs.legacyPackages.${system},
          }:
          let
            app =
              system:
              mkApp {
                pkgs = pkgsFor system;
                inherit
                  nodes
                  masterRecipients
                  masterIdentities
                  agePlugins
                  ;
              };
          in
          {
            packages = lib.genAttrs systems (system: {
              sops-rekey = app system;
            });
            apps = lib.genAttrs systems (system: {
              sops-rekey = {
                type = "app";
                program = lib.getExe (app system);
              };
            });
          };
      };

      packages = forAllSystems (pkgs: {
        default = pkgs.callPackage ./nix/package.nix { };
        sops-rekey-test = testApp pkgs;
      });

      checks = forAllSystems (pkgs: {
        integration = import ./tests/integration.nix {
          inherit pkgs self;
          app = testApp pkgs;
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            sops
            age
            ssh-to-age
            gnupg
            jq
          ];
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
