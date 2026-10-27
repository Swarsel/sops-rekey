{
  alnum =
    { pkgs, ... }:
    ''
      ${pkgs.coreutils}/bin/tr -dc '[:alnum:]' < /dev/urandom | ${pkgs.coreutils}/bin/head -c 48
    '';

  base64 =
    { pkgs, ... }:
    ''
      ${pkgs.openssl}/bin/openssl rand -base64 32 | ${pkgs.coreutils}/bin/tr -d '\n'
    '';

  hex =
    { pkgs, ... }:
    ''
      ${pkgs.openssl}/bin/openssl rand -hex 24 | ${pkgs.coreutils}/bin/tr -d '\n'
    '';

  passphrase =
    { pkgs, ... }:
    ''
      ${pkgs.xkcdpass}/bin/xkcdpass --numwords=6 --delimiter=' ' | ${pkgs.coreutils}/bin/tr -d '\n'
    '';

  dhparams =
    { pkgs, ... }:
    ''
      ${pkgs.openssl}/bin/openssl dhparam 4096 2>/dev/null
    '';

  ssh-ed25519 =
    {
      pkgs,
      lib,
      name,
      pubFile,
      ...
    }:
    ''
      set -euo pipefail
      priv=$( (exec 3>&1; ${pkgs.openssh}/bin/ssh-keygen -q -t ed25519 -N "" -C ${lib.escapeShellArg name} -f /proc/self/fd/3 <<<y >/dev/null 2>&1; true) )
      printf '%s\n' "$priv" | ${pkgs.openssh}/bin/ssh-keygen -y -f /proc/self/fd/0 > ${lib.escapeShellArg pubFile}
      printf '%s\n' "$priv"
    '';

  wireguard =
    {
      pkgs,
      lib,
      pubFile,
      ...
    }:
    ''
      set -euo pipefail
      priv=$(${pkgs.wireguard-tools}/bin/wg genkey)
      printf '%s' "$priv" | ${pkgs.wireguard-tools}/bin/wg pubkey > ${lib.escapeShellArg pubFile}
      printf '%s' "$priv"
    '';

  age =
    {
      pkgs,
      lib,
      pubFile,
      ...
    }:
    ''
      set -euo pipefail
      priv=$(${pkgs.age}/bin/age-keygen 2>/dev/null | ${pkgs.gnugrep}/bin/grep '^AGE-SECRET-KEY-')
      printf '%s\n' "$priv" | ${pkgs.age}/bin/age-keygen -y > ${lib.escapeShellArg pubFile}
      printf '%s\n' "$priv"
    '';
}
