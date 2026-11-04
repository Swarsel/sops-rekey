{
  pkgs,
  testHosts,
  modules,
}:
pkgs.testers.runNixOSTest {
  name = "sops-rekey";
  nodes = builtins.mapAttrs (_: m: { imports = modules ++ [ m ]; }) testHosts;
  testScript = ''
    start_all()
    for m in [host1, host2]:
        m.wait_for_unit("multi-user.target")
        m.succeed("test \"$(cat /run/secrets/shared)\" = shared-value")

    host1.succeed("test \"$(cat /run/secrets/only)\" = only-host1")
    host2.succeed("printf 'binary\\ncontent' | cmp - /run/secrets/blob")
  '';
}
