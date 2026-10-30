{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "sops-rekey";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../cli;
    fileset = lib.fileset.unions [
      ../cli/Cargo.toml
      ../cli/Cargo.lock
      ../cli/src
    ];
  };
  cargoLock.lockFile = ../cli/Cargo.lock;
  meta = {
    description = "Rekey and generate sops secrets for NixOS hosts";
    license = lib.licenses.mit;
    mainProgram = "sops-rekey";
  };
}
