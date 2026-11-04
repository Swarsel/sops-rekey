#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
f=tests/fixtures
rm -rf "$f"
mkdir -p "$f/secrets"

age-keygen -o "$f/master.key" 2>/dev/null
age-keygen -y "$f/master.key" > "$f/master.pub"
age-keygen 2>/dev/null | age-keygen -y > "$f/extra.pub"
for h in host1 host2; do
  ssh-keygen -q -t ed25519 -N "" -C "$h" -f "$f/${h}_ed25519"
done

recipients=$(cat "$f/master.pub"),$(cat "$f/extra.pub")
enc() { sops --config /dev/null encrypt --age "$recipients" --filename-override "$1" /dev/stdin > "$1"; }

printf 'shared: shared-value\nhost1:\n  only: only-host1\n' | enc "$f/secrets/common.yaml"
printf 'binary\ncontent' | enc "$f/secrets/blob.bin"

git add "$f"
nix run .#sops-rekey-test -- --add-to-git rekey
