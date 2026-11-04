{
  pkgs,
  self,
  app,
}:
pkgs.runCommand "sops-rekey-integration"
  {
    nativeBuildInputs = [
      app
      pkgs.sops
      pkgs.ssh-to-age
      pkgs.wireguard-tools
    ];
  }
  ''
    set -euo pipefail
    export HOME=$TMPDIR
    cp -r ${self} repo
    chmod -R u+w repo
    cd repo
    f=tests/fixtures
    common=tests__fixtures__secrets__common.yaml
    generated=tests__fixtures__secrets__generated.yaml

    get() {
      local extract
      extract=$(printf '%s' "$3" | sed 's|^|["|; s|/|"]["|g; s|$|"]|')
      SOPS_AGE_KEY="$(ssh-to-age -private-key -i "$f/$1_ed25519")" \
        sops --config /dev/null decrypt --extract "$extract" "$f/rekeyed/$2.yaml"
    }
    expect() { [ "$1" = "$2" ] || { echo "FAIL: expected '$2', got '$1'" >&2; exit 1; }; }
    master() { SOPS_AGE_KEY="$(cat $f/master.key)" sops --config /dev/null "$@"; }

    echo "== committed fixtures are up to date"
    sops-rekey check

    echo "== groups follow recipient sets"
    expect "$(ls $f/rekeyed | sort | tr '\n' ' ')" "host1+host2.yaml host1.yaml host2.yaml index.json "
    expect "$(get host1 host1+host2 $common/shared)" shared-value
    expect "$(get host2 host1+host2 $common/shared)" shared-value
    expect "$(get host1 host1 $common/host1/only)" only-host1
    expect "$(get host2 host2 tests__fixtures__secrets__blob.bin)" "$(printf 'binary\ncontent')"
    if get host2 host1 $common/host1/only 2>/dev/null; then echo "FAIL: host2 can read host1's group" >&2; exit 1; fi

    echo "== generators"
    gen=$(get host1 host1+host2 $generated/pw)
    expect "''${#gen}" 48
    expect "$(get host2 host1+host2 $generated/derived)" "derived-$gen"
    expect "$(get host1 host1 $generated/wg/host1 | wg pubkey)" "$(cat $f/secrets/generated/wg/host1.pub)"

    echo "== editing one secret only rekeys the groups using it"
    untouched=$(sha256sum $f/rekeyed/host1.yaml $f/rekeyed/host2.yaml)
    master set $f/secrets/common.yaml '["shared"]' '"changed"'
    if sops-rekey check; then echo "FAIL: check passed after edit" >&2; exit 1; fi
    sops-rekey rekey
    sops-rekey check
    expect "$(get host2 host1+host2 $common/shared)" changed
    expect "$(sha256sum $f/rekeyed/host1.yaml $f/rekeyed/host2.yaml)" "$untouched"

    echo "== forced regeneration cascades to dependents and keeps other leaves"
    wg=$(get host1 host1 $generated/wg/host1)
    host1_before=$(sha256sum $f/rekeyed/host1.yaml)
    sops-rekey generate --force generated
    sops-rekey rekey
    gen2=$(get host1 host1+host2 $generated/pw)
    [ "$gen2" != "$gen" ] || { echo "FAIL: not regenerated" >&2; exit 1; }
    expect "$(get host1 host1+host2 $generated/derived)" "derived-$gen2"
    expect "$(get host1 host1 $generated/wg/host1)" "$wg"
    expect "$(sha256sum $f/rekeyed/host1.yaml)" "$host1_before"

    echo "== update-keys adds recipients without re-encrypting leaves"
    master rotate -i --rm-age "$(cat $f/extra.pub)" $f/secrets/common.yaml
    sops-rekey rekey
    groups_before=$(sha256sum $f/rekeyed/*.yaml)
    sops-rekey update-keys
    expect "$(grep -c 'recipient: age1' $f/secrets/common.yaml)" 2
    if sops-rekey check; then echo "FAIL: index not stale after update-keys" >&2; exit 1; fi
    sops-rekey rekey
    sops-rekey check
    expect "$(sha256sum $f/rekeyed/*.yaml)" "$groups_before"

    echo "== missing secrets are generated, deleted groups recreated"
    rm -r $f/rekeyed $f/secrets/generated.yaml
    sops-rekey rekey
    sops-rekey check
    expect "$(get host2 host1+host2 $generated/derived)" "derived-$(get host2 host1+host2 $generated/pw)"

    echo "== rekey is idempotent"
    before=$(sha256sum $f/rekeyed/*)
    sops-rekey rekey
    expect "$(sha256sum $f/rekeyed/*)" "$before"

    touch $out
  ''
