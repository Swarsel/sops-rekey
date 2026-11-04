let
  fixtures = ./fixtures;

  common =
    name:
    { config, lib, ... }:
    {
      networking.hostName = name;
      sops.defaultSopsFile = fixtures + "/secrets/common.yaml";
      sops.rekey = {
        hostPubkey = fixtures + "/${name}_ed25519.pub";
        keyPrefix = "${name}/";
        storageDir = fixtures + "/rekeyed";
      };
      sops.age.sshKeyPaths = [ "${fixtures + "/${name}_ed25519"}" ];
      sops.gnupg.sshKeyPaths = [ ];

      sops.secrets = {
        shared.rekey.keyPrefix = "";
        generated.rekey = {
          file = fixtures + "/secrets/generated.yaml";
          key = "pw";
          generator = {
            args.length = 16;
            script = "alnum";
          };
        };
        hashed.rekey = {
          file = fixtures + "/secrets/generated.yaml";
          keyPrefix = "";
          generator = {
            dependencies = [ config.sops.secrets.generated ];
            script = "bcrypt";
          };
        };
        derived.rekey = {
          file = fixtures + "/secrets/generated.yaml";
          keyPrefix = "";
          generator = {
            dependencies = [ config.sops.secrets.generated ];
            script =
              { decrypt, deps, ... }:
              ''
                printf 'derived-%s' "$(${decrypt} ${lib.escapeShellArg (builtins.head deps).rekey.id})"
              '';
          };
        };
      };
    };
in
{
  host1 = {
    imports = [ (common "host1") ];
    sops.secrets = {
      only = { };
      wg.rekey = {
        file = fixtures + "/secrets/generated.yaml";
        key = "wg/host1";
        generator.script = "wireguard";
      };
    };
  };

  host2 = {
    imports = [ (common "host2") ];
    sops.secrets.blob.rekey.file = fixtures + "/secrets/blob.bin";
  };
}
