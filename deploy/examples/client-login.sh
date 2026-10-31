#!/usr/bin/env bash
# Pair an API client with an Androvia relay, then log in and print a short-lived access token.
# Needs: bash, curl, openssl, jq, base64.
#
#   First time (the relay administrator gives you a one-time pairing code):
#     ./client-login.sh pair   https://relay.example.com wss://relay.example.com ABCDE-FGHIJ-KLMNO-PQRST-UVWXYZ "my agent"
#   Every login after that (tokens last 10 minutes by default):
#     TOKEN=$(./client-login.sh login https://relay.example.com wss://relay.example.com)
#
# Arguments: <command> <relay https URL> <relay public origin> [pairing code] [label]
#   The public origin must be EXACTLY the relay's RELAY_PUBLIC_ORIGIN (lower case, no trailing slash). The client signs it,
#   so a different relay cannot reuse your signature.
# Files (current directory, override with CLIENT_DIR): client-key.pem (your PRIVATE key, keep it secret, chmod 600) and
# client.json (ids only, not secret).
set -euo pipefail

cmd="${1:?usage: $0 pair|login <https url> <public origin> [code] [label]}"
url="${2:?relay https url}"
origin="${3:?relay public origin, e.g. wss://relay.example.com}"
dir="${CLIENT_DIR:-.}"
key="$dir/client-key.pem"
ids="$dir/client.json"

case "$cmd" in
  pair)
    code="${4:?pairing code}"
    label="${5:-api client}"
    [ -f "$key" ] && { echo "refusing to overwrite $key" >&2; exit 1; }
    (umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$key")
    spki="$(openssl ec -in "$key" -pubout -outform DER 2>/dev/null | base64 -w0)"
    curl -sf -X POST "$url/v1/clients/redeem" \
      -d "$(jq -n --arg c "$code" --arg l "$label" --arg k "$spki" '{code:$c,label:$l,public_key:$k}')" \
      | jq '{client_id, credential_id}' > "$ids"
    echo "paired as $(jq -r .client_id "$ids")" >&2
    ;;
  login)
    client_id="$(jq -r .client_id "$ids")"
    cred_id="$(jq -r .credential_id "$ids")"
    nonce="$(curl -sf -X POST "$url/v1/auth/challenge" -d "$(jq -n --arg c "$client_id" '{client_id:$c}')" | jq -r .nonce)"
    # The signed bytes: "androvia/client-auth/v1" NUL || nonce (32 raw bytes) || client id || credential id || origin
    sig="$( { printf 'androvia/client-auth/v1\0'; printf '%s' "$nonce" | base64 -d; printf '%s%s%s' "$client_id" "$cred_id" "$origin"; } \
            | openssl dgst -sha256 -sign "$key" | base64 -w0)"
    curl -sf -X POST "$url/v1/auth/token" \
      -d "$(jq -n --arg c "$client_id" --arg k "$cred_id" --arg n "$nonce" --arg s "$sig" '{client_id:$c,credential_id:$k,nonce:$n,signature:$s}')" \
      | jq -r .access_token
    ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
