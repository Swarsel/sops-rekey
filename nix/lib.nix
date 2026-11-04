{ lib }:
rec {
  relPath =
    p:
    let
      s = toString p;
      m = builtins.match "/nix/store/[^/]+/(.*)" s;
    in
    if m == null then
      throw "sops-rekey: ${s} must be a path inside your flake (e.g. ./secrets/x.yaml)"
    else
      builtins.head m;

  escape = builtins.replaceStrings [ "/" ] [ "__" ];

  isBinary =
    file:
    let
      ext = lib.last (lib.splitString "." (baseNameOf (toString file)));
    in
    !(builtins.elem ext [
      "yaml"
      "yml"
      "json"
      "env"
      "ini"
    ]);

  secretId = file: key: escape (relPath file) + lib.optionalString (key != null) "/${key}";

  pubFile =
    file: key:
    let
      base = baseNameOf (toString file);
      m = builtins.match "(.*)\\.[^.]*" base;
      stem = if m == null then base else builtins.head m;
    in
    dirOf file + (if key == null then "/${stem}.pub" else "/${stem}/${key}.pub");
}
