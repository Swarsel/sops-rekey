# sops-rekey

If you ever wished you had just gone with [agenix](https://github.com/ryantm/agenix) instead of [sops-nix](https://github.com/Mic92/sops-nix) in order to be able to use [agenix-rekey](https://github.com/oddlama/agenix-rekey), then fret no more! This module "ports" its functionality to sops :)

## Setup

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sops-nix.url = "github:Mic92/sops-nix";
    sops-rekey.url = "github:Swarsel/sops-rekey";
  };

  outputs = { self, nixpkgs, sops-nix, sops-rekey, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [ sops-nix.nixosModules.sops sops-rekey.nixosModules.default ./host.nix ];
    };

    apps = (sops-rekey.lib.configure {
      nodes = self.nixosConfigurations;
      masterRecipients.pgp = [ "<fingerprint>" ];
    }).apps;
  };
}
```

With flake-parts:

```nix
{
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    sops-nix.url = "github:Mic92/sops-nix";
    sops-rekey.url = "github:Swarsel/sops-rekey";
  };

  outputs = inputs@{ flake-parts, nixpkgs, sops-nix, sops-rekey, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ sops-rekey.flakeModule ];
      systems = [ "x86_64-linux" ];

      sops-rekey.masterRecipients.pgp = [ "<fingerprint>" ];

      flake.nixosConfigurations.host = nixpkgs.lib.nixosSystem {
        modules = [ sops-nix.nixosModules.sops sops-rekey.nixosModules.default ./host.nix ];
      };
    };
}
```


## Usage

On the hosts:

```nix
{
  sops = {

    defaultSopsFile = ./secrets/common.yaml;
    rekey = {
      hostPubkey = "ssh-ed25519 AAAA...";
      storageDir = ./rekeyed;
    };

    secrets = {
      normalSecret = { };
      defaultRekeyedSecret.rekey = { key = "rekeyedSecret"; };
      rekeyedSecret.rekey = { file = ./secrets/local.yaml; };
      generatedSecret.rekey.generator.script = "wireguard";
    };
  };
}
```

In the above example, as soon as `nix run .#sops-rekey -- rekey` is called (this is preferable as it will automatically build and pick the correct manifest):
- `normalSecret` is not touched by this module
- `defaultRekeyedSecret` looks for a key called `rekeyedSecret` in `./secrets/common.yaml`
- `rekeyedSecret` looks for a key called `rekeyedSecret` in `./secrets/local.yaml`.
- `generatedSecret` generates (only when missing) a WireGuard private key into `generatedSecret` in `./secrets/common.yaml` and writes the matching public key to `./secrets/common/generatedSecret.pub` (you can override this location using `[...].rekey.pubFile`). Also see the [complete set of generators](https://github.com/Swarsel/sops-rekey/blob/main/nix/generators.nix).

All of the above "managed" secrets are then rekeyed  into `./rekeyed/<name>.yaml`. `<name>` is the hostnames that use this secret, concatenated with `+`.
