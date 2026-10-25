{
  config,
  lib,
  options,
  pkgs,
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
        secrets = { };
        groups = { };
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
        else if !builtins.pathExists r.file then
          "its master file ${rl.relPath r.file} does not exist (run `sops-rekey rekey`, or check that it is added to git)"
        else if entry == null then
          "it has not been rekeyed yet"
        else if entry.masterHash != builtins.hashFile "sha256" r.file then
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

  generatorType = types.submodule {
    options = {
      script = mkOption {
        type = types.either types.str (types.functionTo types.str);
        description = ''
          Name of a generator in `sops.rekey.generators`, or a function
          `{ pkgs, lib, name, secret, file, pubFile, decrypt, deps, ... }: "<shell script>"`
          whose script prints the secret to stdout.
        '';
      };
      dependencies = mkOption {
        type = types.listOf types.unspecified;
        default = [ ];
        description = ''
          Other secrets (e.g. `config.sops.secrets.foo`, or another host's via
          flake outputs) this generator reads using `decrypt`. They are
          generated first, and regenerating them regenerates this secret.
        '';
      };
      tags = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Tags for `sops-rekey generate --tags`.";
      };
    };
  };
in
{
  options.sops.rekey = {
    hostPubkey = mkOption {
      type = types.nullOr (types.either types.str types.path);
      default = null;
      example = "ssh-ed25519 AAAAC3Nza...";
      description = ''
        Public key this host decrypts its secrets with: an age recipient, an
        `ssh-ed25519` public key (converted with ssh-to-age, matching sops-nix's
        `sops.age.sshKeyPaths`), or a path to a file containing one.
      '';
    };

    allowMissingPubkey = mkOption {
      type = types.bool;
      default = true;
      description = ''
        If `hostPubkey` is unset, warn and give this host no rekeyed secrets
        (for bootstrapping) instead of failing evaluation.
      '';
    };

    storageDir = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = lib.literalExpression "./rekeyed";
      description = ''
        Directory inside the flake holding the rekeyed group files and
        `index.json`. Must be the same for all hosts.
      '';
    };

    generators = mkOption {
      type = types.attrsOf (types.functionTo types.str);
      default = { };
      description = "Named generators usable as `rekey.generator.script = \"<name>\"`.";
    };

    hostPubkeyString = mkOption {
      type = types.nullOr types.str;
      internal = true;
      readOnly = true;
      default = hostPubkey;
    };
  };

  options.sops.secrets = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          r = config.rekey;
        in
        {
          options.rekey = {
            enable = mkOption {
              type = types.bool;
              default = r.file != null;
              defaultText = lib.literalExpression "rekey.file != null";
              description = "Whether this secret is rekeyed from a master file.";
            };
            file = mkOption {
              type = types.nullOr types.path;
              default = defaultMasterFile;
              defaultText = lib.literalExpression "config.sops.defaultSopsFile";
              description = ''
                Master file containing this secret (inside the flake). Defaults to
                `sops.defaultSopsFile`, so with it set every secret is rekeyed
                unless it sets `rekey.enable = false`.
              '';
            };
            key = mkOption {
              type = types.nullOr types.str;
              default = if r.file != null && rl.isBinary r.file then null else name;
              defaultText = lib.literalMD "the secret's name, or `null` for binary master files";
              description = "`/`-separated key path in the master file; `null` for the whole (binary) file.";
            };
            generator = mkOption {
              type = types.nullOr generatorType;
              default = null;
              description = "How to generate this secret if it does not exist.";
            };
            id = mkOption {
              type = types.str;
              readOnly = true;
              default = rl.secretId r.file r.key;
              defaultText = lib.literalMD "derived from `file` and `key`";
              description = "Identifier of the master secret, shared by all hosts using it.";
            };
            pubFile = mkOption {
              type = types.path;
              readOnly = true;
              default = rl.pubFile r.file r.key;
              defaultText = lib.literalMD "`<dir>/<stem>.<key>.pub` next to the master file";
              description = ''
                Public part written by generators such as `ssh-ed25519` or
                `wireguard`; read it with `builtins.readFile`.
              '';
            };
            __toString = mkOption {
              type = types.unspecified;
              internal = true;
              readOnly = true;
              default = _: "sops-rekey";
            };
          };

          config = lib.mkIf r.enable {
            sopsFile =
              if hostPubkey != null && (resolve config).problem == null then
                (resolve config).file
              else
                placeholder;
            key = r.id;
            format = "yaml";
          };
        }
      )
    );
  };

  config = {
    sops.validateSopsFiles = lib.mkIf (hostPubkey == null && rekeyed != { }) (lib.mkDefault false);

    warnings = lib.optional (hostPubkey == null && rekeyed != { } && cfg.allowMissingPubkey) ''
      sops-rekey: sops.rekey.hostPubkey is not set, so this host gets none of its
      ${toString (builtins.length (builtins.attrNames rekeyed))} rekeyed secrets. Set it and run `sops-rekey rekey`.
    '';

    assertions = [
      {
        assertion = options.sops ? defaultSopsFile;
        message = "sops-rekey: import the sops-nix NixOS module as well.";
      }
      {
        assertion = hostPubkey != null || cfg.allowMissingPubkey || rekeyed == { };
        message = "sops-rekey: sops.rekey.hostPubkey must be set (allowMissingPubkey is false).";
      }
      {
        assertion = hostPubkey == null || problems == { };
        message =
          "sops-rekey: some secrets are out of date, run `sops-rekey rekey` (and `git add` the results):\n"
          + lib.concatStringsSep "\n" (lib.mapAttrsToList (n: p: "  - ${n}: ${p}") problems);
      }
    ]
    ++ lib.mapAttrsToList (n: s: {
      assertion = s.rekey.generator == null || s.rekey.enable;
      message = "sops-rekey: sops.secrets.${n} has a generator but is not rekeyed (set rekey.file).";
    }) config.sops.secrets;
  };
}
