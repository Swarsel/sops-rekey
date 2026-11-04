{
  config,
  lib,
  pkgs,
  options,
  ...
}:
let
  inherit (lib) mkOption types;
  rl = import ./lib.nix { inherit lib; };
  cfg = config.sops.rekey;

  defaultMasterFile =
    if options.sops ? defaultSopsFile && options.sops.defaultSopsFile.isDefined then
      config.sops.defaultSopsFile
    else
      null;

  hostPubkey =
    if cfg.hostPubkey == null then
      null
    else if builtins.isPath cfg.hostPubkey || lib.hasPrefix "/" cfg.hostPubkey then
      lib.trim (builtins.readFile cfg.hostPubkey)
    else
      lib.trim cfg.hostPubkey;

  index =
    let
      file = cfg.storageDir + "/index.json";
    in
    if cfg.storageDir != null && builtins.pathExists file then
      builtins.fromJSON (builtins.readFile file)
    else
      {
        files = { };
        groups = { };
        secrets = { };
      };

  resolve =
    secret:
    let
      r = secret.rekey;
      entry = index.secrets.${r.id} or null;
      group = if entry == null then null else index.groups.${entry.group} or null;
      file = cfg.storageDir + "/${entry.group}.yaml";
    in
    {
      inherit file;
      problem =
        if cfg.storageDir == null then
          "sops.rekey.storageDir is not set"
        else if r.file == null then
          "it has no master file (set rekey.file or sops.defaultSopsFile)"
        else if !builtins.pathExists r.file then
          "its master file ${rl.relPath r.file} does not exist (run `sops-rekey rekey`, or check that it is added to git)"
        else if entry == null then
          "it has not been rekeyed yet"
        else if (index.files.${rl.relPath r.file} or null) != builtins.hashFile "sha256" r.file then
          "${rl.relPath r.file} changed since the last rekey"
        else if group == null || !(builtins.elem hostPubkey (builtins.attrValues group.hosts)) then
          "its rekeyed file is not encrypted for this host's current pubkey"
        else if !builtins.pathExists file then
          "${rl.relPath file} is missing (is it added to git?)"
        else
          null;
    };

  placeholder = pkgs.writeText "sops-rekey-placeholder.yaml" "{}\n";

  rekeyed = lib.filterAttrs (_: s: s.rekey.enable) config.sops.secrets;
  problems = lib.filterAttrs (_: p: p != null) (lib.mapAttrs (_: s: (resolve s).problem) rekeyed);

  isHomeManager = options ? home;

  generatorType = types.submodule {
    options = {
      args = mkOption {
        default = { };
        description = ''
          Passed to the generator function as `args`. The built-in `alnum`,
          `hex`, `base64` and `base64url` read `length` from it.
        '';
        type = types.attrsOf types.anything;
      };
      dependencies = mkOption {
        default = [ ];
        description = ''
          Other secrets (e.g. `config.sops.secrets.foo`, or another host's via
          flake outputs) this generator reads using `decrypt`. They are
          generated first, and regenerating them regenerates this secret.
        '';
        type = types.listOf types.unspecified;
      };
      script = mkOption {
        description = ''
          Name of a generator in `sops.rekey.generators`, or a function
          `{ pkgs, lib, name, secret, file, pubFile, decrypt, deps, args, ... }: "<shell script>"`
          whose script prints the secret to stdout.
        '';
        type = types.either types.str (types.functionTo types.str);
      };
      tags = mkOption {
        default = [ ];
        description = "Tags for `sops-rekey generate --tags`.";
        type = types.listOf types.str;
      };
    };
  };
in
{
  options.sops = {
    rekey = {
      allowMissingPubkey = mkOption {
        default = true;
        description = ''
          If `hostPubkey` is unset, warn and give this host no rekeyed secrets
          (for bootstrapping) instead of failing evaluation.
        '';
        type = types.bool;
      };
      generators = mkOption {
        default = { };
        description = "Named generators usable as `rekey.generator.script = \"<name>\"`.";
        type = types.attrsOf (types.functionTo types.str);
      };
      hostPubkey = mkOption {
        default = null;
        description = ''
          Public key this host decrypts its secrets with: an age recipient, an
          `ssh-ed25519` public key (converted with ssh-to-age, matching sops-nix's
          `sops.age.sshKeyPaths`), or a path to a file containing one.
        '';
        example = "ssh-ed25519 AAAAC3Nza...";
        type = types.nullOr (types.either types.str types.path);
      };
      hostPubkeyString = mkOption {
        default = hostPubkey;
        internal = true;
        readOnly = true;
        type = types.nullOr types.str;
      };
      keyPrefix = mkOption {
        default = "";
        description = ''
          Prepended to the default `rekey.key` of every secret, so that hosts
          sharing one master file each get their own namespace in it.
        '';
        example = lib.literalExpression ''"hosts/''${config.networking.hostName}/"'';
        type = types.str;
      };
      rekeyAllSecrets = mkOption {
        default = false;
        description = ''
          Rekey every secret that has a master file, as if each one set
          `rekey`. Individual secrets can still opt out with
          `rekey.enable = false`.
        '';
        type = types.bool;
      };
      storageDir = mkOption {
        default = null;
        description = ''
          Directory inside the flake holding the rekeyed group files and
          `index.json`. Must be the same for all hosts.
        '';
        example = lib.literalExpression "./rekeyed";
        type = types.nullOr types.path;
      };
    };
    secrets = mkOption {
      type = types.attrsOf (
        types.submodule (
          {
            name,
            config,
            options,
            ...
          }:
          let
            r = config.rekey;
          in
          {
            options.rekey = mkOption {
              default = { };
              description = ''
                Rekeying of this secret. Setting it to anything, even `{ }`, makes
                the secret rekeyed from its master file; secrets without it are
                left to sops-nix as they are unless `sops.rekey.rekeyAllSecrets` is set.
              '';
              type = types.submodule {
                options = {
                  enable = mkOption {
                    default =
                      (cfg.rekeyAllSecrets && r.file != null)
                      || options.rekey.highestPrio < (lib.mkOptionDefault null).priority;
                    defaultText = lib.literalMD "`true` if `rekey` is set at all, or if `sops.rekey.rekeyAllSecrets` is set and the secret has a master file";
                    description = "Whether this secret is rekeyed from a master file.";
                    type = types.bool;
                  };
                  __toString = mkOption {
                    default = _: "sops-rekey";
                    internal = true;
                    readOnly = true;
                    type = types.unspecified;
                  };
                  file = mkOption {
                    default = defaultMasterFile;
                    defaultText = lib.literalExpression "config.sops.defaultSopsFile";
                    description = "Master file containing this secret (inside the flake).";
                    type = types.nullOr types.path;
                  };
                  generator = mkOption {
                    default = null;
                    description = "How to generate this secret if it does not exist.";
                    type = types.nullOr generatorType;
                  };
                  id = mkOption {
                    default = rl.secretId r.file r.key;
                    defaultText = lib.literalMD "derived from `file` and `key`";
                    description = "Identifier of the master secret, shared by all hosts using it.";
                    readOnly = true;
                    type = types.str;
                  };
                  key = mkOption {
                    default = if r.file != null && rl.isBinary r.file then null else r.keyPrefix + name;
                    defaultText = lib.literalMD "`rekey.keyPrefix` + the secret's name, or `null` for binary master files";
                    description = "`/`-separated key path in the master file; `null` for the whole (binary) file.";
                    type = types.nullOr types.str;
                  };
                  keyPrefix = mkOption {
                    default = cfg.keyPrefix;
                    defaultText = lib.literalExpression "config.sops.rekey.keyPrefix";
                    description = "Prefix of the default `rekey.key`, for secrets living in another namespace of the master file.";
                    type = types.str;
                  };
                  pubFile = mkOption {
                    default = rl.pubFile r.file r.key;
                    defaultText = lib.literalMD "`<dir>/<stem>/<key>.pub` next to the master file (`<dir>/<stem>.pub` for binary files)";
                    description = ''
                      Where generators such as `ssh-ed25519` or `wireguard` write the
                      public part; read it with `builtins.readFile`. Must be inside the
                      flake and the same on every host using this secret.
                    '';
                    type = types.path;
                  };
                };
              };
            };

            config = lib.mkIf r.enable {
              format = "yaml";
              key = r.id;
              sopsFile =
                if hostPubkey != null && (resolve config).problem == null then
                  (resolve config).file
                else
                  placeholder;
            };
          }
        )
      );
    };
  };

  config = {
    sops = {
      rekey.generators = lib.mapAttrs (_: lib.mkDefault) (import ./generators.nix);
      validateSopsFiles = lib.mkIf (hostPubkey == null && rekeyed != { }) (lib.mkDefault false);
    };
    assertions = [
      {
        assertion = options.sops ? defaultSopsFile;
        message = "sops-rekey: import the sops-nix module as well.";
      }
      {
        assertion = hostPubkey != null || cfg.allowMissingPubkey || rekeyed == { };
        message = "sops-rekey: sops.rekey.hostPubkey must be set (allowMissingPubkey is false).";
      }
      {
        assertion = isHomeManager || hostPubkey == null || problems == { };
        message =
          "sops-rekey: some secrets are out of date, run `sops-rekey rekey` (and `git add` the results):\n"
          + lib.concatStringsSep "\n" (lib.mapAttrsToList (n: p: "  - ${n}: ${p}") problems);
      }
    ]
    ++ lib.mapAttrsToList (n: s: {
      assertion = s.rekey.generator == null || s.rekey.enable;
      message = "sops-rekey: sops.secrets.${n} has a generator but sets rekey.enable = false.";
    }) config.sops.secrets;
    warnings = lib.optional (hostPubkey == null && rekeyed != { } && cfg.allowMissingPubkey) ''
      sops-rekey: sops.rekey.hostPubkey is not set, so this host gets none of its
      ${toString (builtins.length (builtins.attrNames rekeyed))} rekeyed secrets. Set it and run `sops-rekey rekey`.
    '';
  };
}
