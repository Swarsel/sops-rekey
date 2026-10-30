{
  lib,
  pkgs,
  nodes,
  masterRecipients ? { },
  masterIdentities ? [ ],
  agePlugins ? (_: [ ]),
}:
let
  cli = pkgs.callPackage ./package.nix { };
  manifest = pkgs.writeText "sops-rekey-manifest.json" (
    builtins.toJSON (
      import ./manifest.nix {
        inherit
          lib
          pkgs
          nodes
          masterRecipients
          masterIdentities
          ;
      }
    )
  );
in
pkgs.writeShellScriptBin "sops-rekey" ''
  export PATH=${
    lib.makeBinPath (
      [
        pkgs.sops
        pkgs.ssh-to-age
        pkgs.age
      ]
      ++ agePlugins pkgs
    )
  }:''${PATH:+$PATH:}${
    lib.makeBinPath [
      pkgs.gnupg
      pkgs.git
    ]
  }
  exec ${lib.getExe cli} --manifest ${manifest} "$@"
''
