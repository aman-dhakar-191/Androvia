#!/usr/bin/env bash
# End-to-end MCP check with three independent implementations: the Go relay (official Go MCP SDK), a simulated phone, and the
# official PYTHON MCP SDK as the client, with the client paired and logged in using only curl and openssl.
#
# It also drives the real `mcpbridge` binary over stdio (no token on the client side) when BRIDGE_BIN is set.
#
# Needs: a PostgreSQL URL for a disposable database, built binaries, python with the `mcp` package, curl, openssl, jq.
#   RELAY_DATABASE_URL=postgres://... RELAY_BIN=... SIM_BIN=... [BRIDGE_BIN=...] PYTHON=python3 scripts/mcp-interop.sh
set -euo pipefail

: "${RELAY_DATABASE_URL:?set RELAY_DATABASE_URL to a disposable database}"
: "${RELAY_BIN:?path to the built relay}"
: "${SIM_BIN:?path to the built simdevice}"
PY="${PYTHON:-python3}"
PORT="${PORT:-18447}"
here="$(cd "$(dirname "$0")/.." && pwd)"
ex="$here/deploy/examples"
U="http://127.0.0.1:$PORT"; O="ws://127.0.0.1:$PORT"
ADMIN="interop-admin-token-$(openssl rand -hex 16)"
work="$(mktemp -d)"; pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$work"; }
trap cleanup EXIT
ok()   { echo "  ok   - $*"; }
die()  { echo "  FAIL - $*" >&2; echo "--- relay log:" >&2; tail -30 "$work/relay.log" >&2 || true; exit 1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

RELAY_DATABASE_URL="$RELAY_DATABASE_URL" RELAY_ADMIN_TOKEN="$ADMIN" RELAY_PUBLIC_ORIGIN="$O" RELAY_ALLOW_INSECURE_HTTP=true RELAY_OAUTH_ENABLED=true \
  RELAY_LISTEN_ADDR="127.0.0.1:$PORT" "$RELAY_BIN" >"$work/relay.log" 2>&1 & pids+=($!)
for _ in $(seq 1 40); do curl -sf "$U/healthz" >/dev/null && break; sleep 0.5; done
curl -sf "$U/healthz" >/dev/null || die "relay did not start"
ok "relay is up"

adm() { curl -sf -H "Authorization: Bearer $ADMIN" "$@"; }
eval "$("$SIM_BIN" -key "$work/phone.pem" -print-registration | sed 's/^/DEV_/')"
adm -X POST "$U/v1/admin/devices" -d "{\"label\":\"sim phone\",\"public_key\":\"$DEV_public_key\"}" >/dev/null || die "register device"
PAIR="$(adm -X POST "$U/v1/admin/pairing-codes" -d "{\"grants\":[{\"device_id\":\"$DEV_device_id\",\"scopes\":[\"devices:read\",\"capability:device.info:execute\"]}]}" | jq -r .code)"
CLIENT_DIR="$work" "$ex/client-login.sh" pair "$U" "$O" "$PAIR" "interop client" 2>/dev/null || die "pairing with curl+openssl"
TOKEN="$(CLIENT_DIR="$work" "$ex/client-login.sh" login "$U" "$O")" || die "login with curl+openssl"
ok "client paired and logged in with only curl and openssl"

"$SIM_BIN" -key "$work/phone.pem" -relay "$O" -allow-insecure >"$work/sim.log" 2>&1 & pids+=($!)
for _ in $(seq 1 40); do [ "$(curl -sf "$U/v1/devices" -H "Authorization: Bearer $TOKEN" | jq -r '.devices[0].online')" = "true" ] && break; sleep 0.5; done
[ "$(curl -sf "$U/v1/devices" -H "Authorization: Bearer $TOKEN" | jq -r '.devices[0].online')" = "true" ] || die "simulated phone did not connect"
ok "simulated phone is online"

echo "Python MCP SDK, initialize handshake (protocol 2025-11-25):"
"$PY" "$ex/mcp_client.py" "$U/mcp" "$TOKEN" "$DEV_device_id" | sed 's/^/    /' || die "python client (initialize)"
echo "Python MCP SDK, stateless discover (protocol 2026-07-28):"
"$PY" "$ex/mcp_client.py" --discover "$U/mcp" "$TOKEN" "$DEV_device_id" | sed 's/^/    /' || die "python client (discover)"
ok "both protocol revisions work end to end"

echo "Python MCP SDK OAuth client (discovery, registration, PKCE, owner approval, refresh, replay):"
"$PY" "$ex/mcp_oauth_client.py" "$U/mcp" "$ADMIN" "$DEV_device_id" | sed 's/^/    /' || die "python OAuth client"
ok "a remote-host style OAuth connection works end to end"

if [ -n "${BRIDGE_BIN:-}" ]; then
  echo "stdio bridge (mcpbridge), the client holds no token:"
  BDIR="$work/bridge"
  BCODE="$(adm -X POST "$U/v1/admin/pairing-codes" -d "{\"grants\":[{\"device_id\":\"$DEV_device_id\",\"scopes\":[\"devices:read\",\"capability:device.info:execute\"]}]}" | jq -r .code)"
  ANDROVIA_PAIRING_CODE="$BCODE" "$BRIDGE_BIN" pair -relay "$U" -allow-insecure -dir "$BDIR" -label "interop bridge" 2>"$work/pair.err" || { cat "$work/pair.err" >&2; die "mcpbridge pair"; }
  [ "$(stat -c %a "$BDIR/client-key.pem")" = 600 ] || die "bridge key is not mode 600"
  ok "mcpbridge paired itself (key mode 600)"
  # With no -origin the bridge signs ws://<host:port> for an http:// relay, which is exactly this relay's RELAY_PUBLIC_ORIGIN.
  BR=("$BRIDGE_BIN" run -relay "$U" -allow-insecure -dir "$BDIR")
  "$PY" "$ex/mcp_client.py" --stdio "$DEV_device_id" -- "${BR[@]}" | sed 's/^/    /' || die "python client through the bridge (initialize)"
  "$PY" "$ex/mcp_client.py" --discover --stdio "$DEV_device_id" -- "${BR[@]}" | sed 's/^/    /' || die "python client through the bridge (discover)"
  ok "both protocol revisions work through the bridge"
  BCID="$(jq -r .client_id "$BDIR/client.json")"
  adm -X POST "$U/v1/admin/clients/$BCID/revoke" >/dev/null
  if "$BRIDGE_BIN" run -relay "$U" -allow-insecure -dir "$BDIR" </dev/null 2>"$work/bridge.err"; then die "a revoked client's bridge started"; fi
  grep -qi "rejected" "$work/bridge.err" || die "revoked bridge gave no clear reason: $(cat "$work/bridge.err")"
  ok "a revoked client's bridge refuses to start, with a clear reason"
  ! grep -q "$BCODE" "$work/relay.log" || die "pairing code in the relay log"
fi

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}'
H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
[ "$(code -X POST "$U/mcp" "${H[@]}" -d "$INIT")" = 401 ] || die "unauthenticated /mcp is not 401"
curl -si -X POST "$U/mcp" "${H[@]}" -d "$INIT" | grep -qi '^www-authenticate: bearer.*resource_metadata=' || die "401 lacks WWW-Authenticate with resource_metadata"
[ "$(code -X POST "$U/mcp" "${H[@]}" -H "Authorization: Bearer $ADMIN" -d "$INIT")" = 401 ] || die "the admin token works on /mcp"
[ "$(code -X POST "$U/mcp" "${H[@]}" -H "Authorization: Bearer $TOKEN" -H 'Origin: https://evil.example.com' -d "$INIT")" = 403 ] || die "a foreign Origin was accepted"
[ "$(code -X GET "$U/mcp" -H "Authorization: Bearer $TOKEN" -H 'Accept: text/event-stream')" = 405 ] || die "GET /mcp is not 405"
[ "$(code "$U/.well-known/oauth-protected-resource/mcp")" = 200 ] || die "no protected resource metadata"
ok "401 + WWW-Authenticate, admin token refused, foreign Origin refused, no GET stream, metadata served"

CID="$(jq -r .client_id "$work/client.json")"
adm -X POST "$U/v1/admin/clients/$CID/revoke" >/dev/null
[ "$(code -X POST "$U/mcp" "${H[@]}" -H "Authorization: Bearer $TOKEN" -d "$INIT")" = 401 ] || die "a revoked client's token still works on /mcp"
ok "revoking the client cuts off its MCP access immediately"

! grep -q "$ADMIN" "$work/relay.log" || die "admin token in the relay log"
! grep -q "$TOKEN" "$work/relay.log" || die "client token in the relay log"
ok "no credentials in the relay log"
echo "MCP interop: all checks passed"
