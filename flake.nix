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
          masterRecipients.age = map (f: lib.trim (builtins.readFile ./tests/fixtures/${f})) [
            "master.pub"
            "extra.pub"
          ];
          masterIdentities = [ ./tests/fixtures/master.key ];
        };
    in
    {
      nixosModules.default = ./nix/module.nix;
      homeManagerModules.default = ./nix/module.nix;
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

      checks = forAllSystems (
        pkgs:
        {
          integration = import ./tests/integration.nix {
            inherit pkgs self;
            app = testApp pkgs;
          };
          eval-stale =
            let
              stale = testNodes.host1.extendModules {
                modules = [
                  { sops.rekey.hostPubkey = lib.mkForce (builtins.readFile ./tests/fixtures/host2_ed25519.pub); }
                ];
              };
              result = builtins.tryEval stale.config.system.build.toplevel.drvPath;
            in
            assert !result.success;
            pkgs.runCommand "sops-rekey-eval-stale" { } "touch $out";
          eval-opt-in =
            let
              plain = testNodes.host1.extendModules { modules = [ { sops.secrets.plain = { }; } ]; };
              all = testNodes.host1.extendModules {
                modules = [
                  {
                    sops.rekey.rekeyAllSecrets = true;
                    sops.secrets.plain = { };
                    sops.secrets.excluded.rekey.enable = false;
                  }
                ];
              };
            in
            assert !plain.config.sops.secrets.plain.rekey.enable;
            assert all.config.sops.secrets.plain.rekey.enable;
            assert !all.config.sops.secrets.excluded.rekey.enable;
            pkgs.runCommand "sops-rekey-eval-opt-in" { } "touch $out";
          eval-pub-file =
            let
              custom = ./tests/fixtures/custom.pub;
              withPubFile =
                node: pubFile:
                node.extendModules { modules = [ { sops.secrets.shared.rekey.pubFile = pubFile; } ]; };
              manifestFor = nodes: import ./nix/manifest.nix { inherit lib pkgs nodes; };
              id = testNodes.host1.config.sops.secrets.shared.rekey.id;
              agreeing = manifestFor {
                host1 = withPubFile testNodes.host1 custom;
                host2 = withPubFile testNodes.host2 custom;
              };
              disagreeing = manifestFor {
                host1 = withPubFile testNodes.host1 custom;
                inherit (testNodes) host2;
              };
            in
            assert agreeing.secrets.${id}.pubFile == "tests/fixtures/custom.pub";
            assert !(agreeing.secrets.${id} ? host);
            assert !(builtins.tryEval disagreeing.secrets.${id}).success;
            pkgs.runCommand "sops-rekey-eval-pub-file" { } "touch $out";
        }
        // lib.optionalAttrs (pkgs.stdenv.hostPlatform.system == "x86_64-linux") {
          vm = import ./tests/vm.nix {
            inherit pkgs testHosts;
            modules = [
              sops-nix.nixosModules.sops
              self.nixosModules.default
            ];
          };
        }
      );

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
