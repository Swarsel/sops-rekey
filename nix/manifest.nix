{
  lib,
  pkgs,
  nodes,
  masterRecipients ? { },
  masterIdentities ? [ ],
}:
let
  rl = import ./lib.nix { inherit lib; };

  decrypt = pkgs.writeShellScript "sops-rekey-decrypt" ''
    : "''${SOPS_REKEY_DEPS:=null}"
    printf '%s' "$SOPS_REKEY_DEPS" | ${pkgs.jq}/bin/jq -je --arg id "$1" \
      '.[$id] // error("sops-rekey: \($id) is not a declared dependency of this generator")'
  '';

  participating = lib.filterAttrs (_: n: n.config ? sops && n.config.sops ? rekey) nodes;
  rekeyedSecrets = node: lib.filterAttrs (_: s: s.rekey.enable) node.config.sops.secrets;

  generatorEntry =
    hostName: node: name: s:
    let
      g = s.rekey.generator;
      fn =
        if builtins.isString g.script then
          node.config.sops.rekey.generators.${g.script}
            or (throw "sops-rekey: unknown generator \"${g.script}\" for ${hostName}.sops.secrets.${name}")
        else
          g.script;
      script = fn {
        inherit
          pkgs
          lib
          name
          decrypt
          ;
        inherit (g) args;
        secret = s;
        file = rl.relPath s.rekey.file;
        pubFile = rl.relPath s.rekey.pubFile;
        deps = g.dependencies;
      };
    in
    {
      host = hostName;
      secret = name;
      script = toString (pkgs.writeShellScript "sops-rekey-generator" script);
      dependencies = map (d: d.rekey.id) g.dependencies;
      inherit (g) tags;
    };

  entries = lib.concatLists (
    lib.mapAttrsToList (
      hostName: node:
      lib.mapAttrsToList (name: s: {
        inherit (s.rekey) id;
        file = rl.relPath s.rekey.file;
        inherit (s.rekey) key;
        pubFile = rl.relPath s.rekey.pubFile;
        generators = lib.optional (s.rekey.generator != null) (generatorEntry hostName node name s);
      }) (rekeyedSecrets node)
    ) participating
  );
in
{
  version = 1;
  masterRecipients = {
    pgp = masterRecipients.pgp or [ ];
    age = masterRecipients.age or [ ];
  };
  masterIdentities = map toString masterIdentities;
  hosts = lib.mapAttrs (_: node: {
    pubkey = node.config.sops.rekey.hostPubkeyString;
    storageDir =
      let
        d = node.config.sops.rekey.storageDir;
      in
      if d == null then null else rl.relPath d;
    secrets = lib.mapAttrs (_: s: s.rekey.id) (rekeyedSecrets node);
  }) participating;
  secrets = lib.mapAttrs (
    _: es:
    builtins.removeAttrs (builtins.head es) [ "id" ]
    // {
      generators = lib.concatMap (e: e.generators) es;
    }
  ) (builtins.groupBy (e: e.id) entries);
}
