{
  config,
  lib,
  self,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.sops-rekey;
in
{
  options.sops-rekey = {
    nodes = mkOption {
      type = types.lazyAttrsOf types.unspecified;
      default = self.nixosConfigurations or { };
      defaultText = lib.literalExpression "self.nixosConfigurations";
      description = "NixOS configurations whose secrets are managed.";
    };
    masterRecipients = {
      pgp = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "PGP fingerprints master files are encrypted to.";
      };
      age = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "age recipients master files are encrypted to.";
      };
    };
    masterIdentities = mkOption {
      type = types.listOf (types.either types.path types.str);
      default = [ ];
      description = ''
        age identity files (plain, plugin stubs, or passphrase-encrypted) used
        to decrypt master files. Not needed for PGP, which uses your gpg-agent.
      '';
    };
    agePlugins = mkOption {
      type = types.functionTo (types.listOf types.package);
      default = _: [ ];
      example = lib.literalExpression "pkgs: [ pkgs.age-plugin-yubikey ]";
      description = "age plugins to make available, as a function of pkgs.";
    };
  };

  config.perSystem =
    { pkgs, ... }:
    let
      app = import ./app.nix {
        inherit lib pkgs;
        inherit (cfg)
          nodes
          masterRecipients
          masterIdentities
          agePlugins
          ;
      };
    in
    {
      packages.sops-rekey = app;
      apps.sops-rekey = {
        type = "app";
        program = lib.getExe app;
      };
    };
}
