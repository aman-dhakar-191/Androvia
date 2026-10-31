# Relay (Phase 2)

Go service in `relay/`: the device WebSocket endpoint, a small HTTPS API, command routing and the device registry
(PostgreSQL). See `docs/protocol/envelope.md` for the wire format.

## Status
| Area | State |
|---|---|
| Strict envelope parser, handshake, heartbeat, routing, registry, migrations | Implemented; Go tests pass with the race detector |
| PostgreSQL store and migrations | Implemented; store test run against PostgreSQL 16 |
| Docker image and Compose stack | Written; verified only by the `Relay` CI job |
| Android WebSocket client (`android/api`, wired in `android/runtime`) | Implemented. Tested against a fake relay and against this relay (CI end-to-end job); **never run on a physical device** |
| Pairing, per-client credentials, scopes, DB audit log, rate limiting | Phase 3 / Phase 7, **not implemented** |
| MCP gateway | Phase 4, not implemented |

## Security model in Phase 2 (read this)
* **Device connections are authenticated.** The device proves possession of its registered EC P-256 key by signing a
  fresh 32-byte nonce (`androvia/relay-auth/v1\0 || nonce || deviceID || relayOrigin`). Unknown, revoked and
  wrongly-signed devices get the identical close (`1008 "authentication failed"`), so the endpoint does not reveal
  which ids are registered. A recorded signature is useless on another connection (new nonce each time) or another
  relay (origin is signed).
* **Everything else uses one bootstrap bearer token** (`RELAY_ADMIN_TOKEN`, at least 32 characters, compared in
  constant time, never logged). It can register devices and send any command to any device. This is **not** the final
  design: Phase 3 replaces it with per-client identities and scopes. Treat the token like a root password.
* **The relay is only a router.** It does not decide what a device may do; the device's own policy (deny by default)
  still applies, and a device refusal is passed back as-is.
* TLS is mandatory unless `RELAY_ALLOW_INSECURE_HTTP=true` (development only). Behind a TLS-terminating proxy, set
  `RELAY_PUBLIC_ORIGIN` to the public `wss://` origin the device will use.
* Single instance only: connection state is in memory. Running two relays would break routing and revocation.
* Registration is by key, not approval: anyone holding the admin token can register any key. The "explicit user
  approval on the device" pairing flow is Phase 3.

## Configuration (environment)
| Variable | Required | Meaning |
|---|---|---|
| `RELAY_DATABASE_URL` | yes | PostgreSQL URL. Migrations run at startup |
| `RELAY_ADMIN_TOKEN` | yes | Bootstrap bearer token, 32+ characters |
| `RELAY_PUBLIC_ORIGIN` | yes | e.g. `wss://relay.example.com` (no path); bound into the handshake signature |
| `RELAY_TLS_CERT_FILE`, `RELAY_TLS_KEY_FILE` | one of TLS / dev flag | Serve TLS directly |
| `RELAY_ALLOW_INSECURE_HTTP` | no | `true` allows plain HTTP / `ws://` (development only) |
| `RELAY_LISTEN_ADDR` | no | default `:8443` |

The relay refuses to start if any rule is violated and reports all problems at once.

## HTTP API
All routes except `/healthz` need `Authorization: Bearer <RELAY_ADMIN_TOKEN>`. Bodies are JSON, max 64 KiB, unknown
fields are rejected. Errors look like `{"error":{"code":"…","message":"…"}}`.

| Route | Purpose |
|---|---|
| `GET /healthz` | liveness, no auth |
| `POST /v1/devices` | `{"label","public_key"}` (base64 SPKI DER, EC P-256) → 201. Device id = hex SHA-256 of the key |
| `GET /v1/devices`, `GET /v1/devices/{id}` | list / get, includes `online` |
| `POST /v1/devices/{id}/revoke` | revoke and disconnect immediately |
| `POST /v1/devices/{id}/commands` | `{"capability","version","args","timeout_ms"}` (timeout ≤ 55 s, default 10 s) |
| `GET /v1/device/ws` | device WebSocket (own signature auth) |

Command outcomes: `200 {"status":"ok","result":…}`; `422` the device answered with an error (`source:"device"`,
e.g. `permission_denied`); `400 invalid_request`; `404 device_not_found`; `409 device_offline | device_revoked`;
`502 device_disconnected`; `504 timeout` (the relay also sends the device a `cancel`); `401 unauthorized`.

## Limits
Messages ≤ 64 KiB; handshake ≤ 10 s; device dropped after 75 s without any valid message (devices send a heartbeat
every 25 s); connection closed after 5 protocol violations; one connection per device (a new one replaces the old).
There is **no HTTP rate limiting yet** (Phase 7).

## Run locally
```bash
cp deploy/.env.example deploy/.env      # set POSTGRES_PASSWORD and RELAY_ADMIN_TOKEN (openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build
curl localhost:8443/healthz
```
Tests: `cd relay && go test -race ./...`. To include the PostgreSQL store test set `RELAY_TEST_DATABASE_URL` to a
disposable database (it deletes all rows in `devices`).
