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

On the hosts:

```nix
{
  sops.defaultSopsFile = ./secrets/common.yaml;
  sops.rekey = {
    hostPubkey = "ssh-ed25519 AAAA...";
    storageDir = ./rekeyed;
  };

  sops.secrets.db-password = { };
  sops.secrets.wg-key.rekey.generator.script = "wireguard";
}
```

## Usage

Run `sops-rekey <command>` from your flake directory:

- `edit <file>` creates or edits a master file, encrypted to `masterRecipients`.
- `rekey` generates missing secrets and re-encrypts every out-of-date file in `storageDir` for its hosts.
- `generate [--force] [--tags <tags>] [<secret>...]` (re)generates secrets
- `update-keys` makes every master file encrypted to exactly `masterRecipients`
- `check` fails if anything needs generating or rekeying
