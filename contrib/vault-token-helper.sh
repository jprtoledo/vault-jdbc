#!/bin/sh
# Vault CLI token helper that keeps one token per Vault server instead of a single ~/.vault-token,
# in the same files vault-jdbc reads (~/.vault-tokens/<address>).
#
# Install:  echo 'token_helper = "/path/to/vault-token-helper.sh"' >> ~/.vault
# Then select the server with VAULT_ADDR (the CLI does not pass -address to token helpers):
#   VAULT_ADDR=https://vault-a.example.com vault login -method=oidc
#   VAULT_ADDR=https://vault-b.example.com vault login -method=oidc
set -eu

dir="${VAULT_JDBC_TOKEN_DIR:-$HOME/.vault-tokens}"
addr="${VAULT_ADDR:-https://127.0.0.1:8200}"
while [ "${addr%/}" != "$addr" ]; do
  addr="${addr%/}"
done
key="$addr"
if [ -n "${VAULT_NAMESPACE:-}" ]; then
  key="$key|$VAULT_NAMESPACE"
fi
# Same file name as vault-jdbc: every character outside [A-Za-z0-9._-] becomes '_'.
name=$(printf '%s' "$key" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_')
file="$dir/$name"

case "${1:-}" in
  get)
    if [ -f "$file" ]; then
      cat "$file"
    fi
    ;;
  store)
    umask 077
    mkdir -p "$dir"
    tmp="$file.$$.tmp"
    cat > "$tmp"
    mv "$tmp" "$file"
    ;;
  erase)
    rm -f "$file"
    ;;
  *)
    echo "usage: $0 get|store|erase" >&2
    exit 1
    ;;
esac
