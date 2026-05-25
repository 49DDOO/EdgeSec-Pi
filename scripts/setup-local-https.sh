#!/usr/bin/env bash
# Generate a local HTTPS certificate for the EdgeSec-Pi bridge.
#
# This is for local/LAN deployments only. Public production deployments should
# use a real domain and a publicly trusted certificate, for example Let's Encrypt.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$ROOT/scripts"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/load-config.sh"
CERT_DIR="$ROOT/scripts/certs"
ENV_FILE="$ROOT/bridge.env"

mkdir -p "$CERT_DIR"

MANAGER_HOST="${MANAGER_HOST:-127.0.0.1}"
BRIDGE_HOST="${BRIDGE_HOST:-$MANAGER_HOST}"
KEYCHAIN="${KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"
TRUST_CA=false
if [[ "${1:-}" == "--trust" ]]; then
  TRUST_CA=true
fi

CA_KEY="$CERT_DIR/edgesec-local-ca.key"
CA_CRT="$CERT_DIR/edgesec-local-ca.crt"
SERVER_KEY="$CERT_DIR/bridge.key"
SERVER_CSR="$CERT_DIR/bridge.csr"
SERVER_CRT="$CERT_DIR/bridge.crt"
SERVER_EXT="$CERT_DIR/bridge.ext"

is_ip() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

ip_index=2
dns_index=2
subject_alt_names=(
  "DNS.1 = localhost"
  "IP.1 = 127.0.0.1"
)
seen_sans=" DNS:localhost IP:127.0.0.1 "

append_san() {
  local host="$1"
  local key
  [[ -z "$host" ]] && return
  if is_ip "$host"; then
    key="IP:$host"
    [[ "$seen_sans" == *" $key "* ]] && return
    subject_alt_names+=("IP.$ip_index = $host")
    ip_index=$((ip_index + 1))
  else
    key="DNS:$host"
    [[ "$seen_sans" == *" $key "* ]] && return
    subject_alt_names+=("DNS.$dns_index = $host")
    dns_index=$((dns_index + 1))
  fi
  seen_sans="$seen_sans$key "
}

for host in "$MANAGER_HOST" "$BRIDGE_HOST"; do
  append_san "$host"
done

if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
  openssl genrsa -out "$CA_KEY" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
    -subj "/CN=EdgeSec-Pi Local CA" \
    -out "$CA_CRT" >/dev/null 2>&1
fi

cat > "$SERVER_EXT" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
$(printf '%s\n' "${subject_alt_names[@]}")
EOF

openssl genrsa -out "$SERVER_KEY" 2048 >/dev/null 2>&1
openssl req -new -key "$SERVER_KEY" \
  -subj "/CN=EdgeSec-Pi Bridge" \
  -out "$SERVER_CSR" >/dev/null 2>&1
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" \
  -CAcreateserial -out "$SERVER_CRT" -days 825 -sha256 \
  -extfile "$SERVER_EXT" >/dev/null 2>&1

chmod 600 "$CA_KEY" "$SERVER_KEY"
chmod 644 "$CA_CRT" "$SERVER_CRT"
rm -f "$SERVER_CSR"

if [[ "$TRUST_CA" == "true" ]]; then
  # Trust this local CA for the current macOS user. Do not use -d here:
  # admin/system trust settings and the login keychain are separate stores.
  security add-trusted-cert -r trustRoot -p ssl -k "$KEYCHAIN" "$CA_CRT"
fi

echo "Local HTTPS certificate ready:"
echo "  CA:     $CA_CRT"
echo "  Cert:   $SERVER_CRT"
echo "  Key:    $SERVER_KEY"
if [[ "$TRUST_CA" == "true" ]]; then
  echo "  Trust:  installed in $KEYCHAIN"
else
  echo "  Trust:  not installed. Run with --trust after explicit approval."
fi
echo "  SAN:"
openssl x509 -in "$SERVER_CRT" -noout -ext subjectAltName
