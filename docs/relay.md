# Relay

Go service in `relay/`: the device WebSocket endpoint, the HTTPS API, command routing, client identities and
authorization, and the audit log (PostgreSQL). Wire format: `docs/protocol/envelope.md`. Design decisions:
`docs/adr/0005-identity-and-authorization.md`.

## Status
| Area | State |
|---|---|
| Device WebSocket: signed challenge handshake, heartbeat, routing | Implemented; Go tests with the race detector |
| Device registry, PostgreSQL store, migrations | Implemented; tested against PostgreSQL 16 |
| **Clients: pairing codes, own EC P-256 keys, signed login, short-lived tokens** | Implemented (Phase 3); tested in Go, Kotlin and with `openssl`/`curl` |
| **Scope-based authorization, deny by default, shared policy engine** | Implemented (Phase 3) |
| **Revocation (client, credential, device) effective on the next request** | Implemented (Phase 3) |
| **Audit log in PostgreSQL with retention; privileged actions fail closed** | Implemented (Phase 3) |
| Android WebSocket client | Implemented; tested against this relay on CI emulators; **never run on a physical phone** |
| Docker image / Compose | Verified by CI only |
| MCP gateway | **Not started** (Phase 4) |
| Approving a pairing on the phone itself | **Not implemented.** Approval is the administrator issuing the code (see "Limits") |
| Role bundles (e.g. "operator"), TLS certificate pinning, production hardening | Not implemented (Phase 7) |

## How things connect
```
Phone (Androvia app) --outbound WSS, signs a challenge with its Keystore key--> RELAY <--HTTPS-- your scripts / agents
                                                                                 ^  (clients sign a challenge with their own key)
                                                                                 |
                                                                  administrator (bootstrap token): devices, pairing, grants, audit
```
1. **Register the phone.** The administrator registers its public key (shown in the app) with `POST /v1/admin/devices`.
2. **The phone connects** (app → Relay card → `wss://…` address → switch on → start the runtime).
3. **Pair a client.** The administrator issues a one-time pairing code that names the devices and scopes it grants. The
   client generates its own key pair, redeems the code, and from then on logs in by signing a challenge.
4. **The client calls the API** with its short-lived bearer token. Each call is checked against its grants; the phone
   then applies its own policy again (a capability must also be switched on in the app).

A runnable example of steps 3 and 4 is `deploy/examples/client-login.sh`.

## Two planes that never overlap
| Plane | Credential | Can do | Cannot do |
|---|---|---|---|
| **Admin** `/v1/admin/...` | `RELAY_ADMIN_TOKEN` (bootstrap token) | register/revoke devices, issue pairing codes, grant/remove scopes, revoke clients, read the audit log | send commands |
| **Client** everything else under `/v1` | access token from a signed login | what its grants allow, on the devices they name | anything on the admin plane |

The admin token is rejected on client routes and client tokens on admin routes (tested). **Treat the admin token like a
root password**: with it someone can pair a new client and grant it access (auditable, but still access). It never
touches a device directly.

## Scopes
No wildcards. A scope is granted per (client, device):
* `devices:read` — see the device and whether it is online
* `capability:<id>:execute` — run that one capability, e.g. `capability:device.info:execute`

Deny by default: no grant means no access. A device the client has no grant on looks exactly like a device that does not
exist (`404 device_not_found`); a device it can see but may not use for that action answers `403 forbidden`.

## Login (clients)
1. `POST /v1/auth/challenge {"client_id"}` → `{"nonce","expires_at"}`. The nonce is 32 random bytes (base64), valid 60 s,
   usable once, bound to that client id. Unknown and revoked clients get a challenge too, so ids cannot be enumerated.
2. Sign (ASN.1 DER ECDSA P-256 / SHA-256) these bytes:
   `"androvia/client-auth/v1" 0x00 || nonce (32 raw bytes) || client_id || credential_id || relay origin`
   where *relay origin* is exactly the relay's `RELAY_PUBLIC_ORIGIN` (e.g. `wss://relay.example.com`). The ids are the
   36-character lower-case UUIDs. Binding the origin means another relay cannot reuse your signature.
3. `POST /v1/auth/token {"client_id","credential_id","nonce","signature"}` → `{"access_token","token_type","expires_at"}`.
   Every failure is the same `401 unauthorized`; the reason is only in the audit log. The challenge is consumed first,
   so a recorded exchange cannot be replayed.
4. Send `Authorization: Bearer <access_token>`. Tokens live in memory, last `RELAY_TOKEN_TTL_MINUTES` (default 10), and
   the client and credential are re-checked on every request.

## API

### Unauthenticated (rate limited per IP)
| Route | Purpose |
|---|---|
| `GET /healthz` | liveness |
| `GET /v1/device/ws` | device WebSocket (signature auth) |
| `POST /v1/auth/challenge`, `POST /v1/auth/token` | client login |
| `POST /v1/clients/redeem` | `{"code","label","public_key"}` (base64 SPKI DER, EC P-256) → `201 {client_id, credential_id, expires_at, grants}`. The code works once; bad input does not burn it |

### Client plane (bearer token)
| Route | Needs | Purpose |
|---|---|---|
| `GET /v1/me` | — | the client, its credentials and grants |
| `POST /v1/me/credentials` | — | rotation: add a replacement key `{"public_key"}` (max 5 active, each valid 365 days) |
| `DELETE /v1/me/credentials/{id}` | — | retire a key; its tokens die at once. The last usable key cannot be removed |
| `GET /v1/devices`, `GET /v1/devices/{id}` | `devices:read` | granted devices, with `online` |
| `POST /v1/devices/{id}/commands` | `capability:<id>:execute` | `{"capability","version","args","timeout_ms"}` (timeout ≤ 55 s, default 10 s) |

Command outcomes: `200 {"status":"ok","result"}`; `422` the device answered with an error (`source:"device"`, e.g.
`permission_denied`); `400 invalid_request`; `403 forbidden`; `404 device_not_found`; `409 device_offline | device_revoked`;
`502 device_disconnected`; `503 audit_unavailable`; `504 timeout`.

### Admin plane (admin token)
| Route | Purpose |
|---|---|
| `POST/GET /v1/admin/devices`, `GET /v1/admin/devices/{id}` | register (`{"label","public_key"}`) / list / get |
| `POST /v1/admin/devices/{id}/revoke` | revoke and disconnect now |
| `POST /v1/admin/pairing-codes` | `{"grants":[{"device_id","scopes"}],"ttl_minutes"}` (default 15, max 1440) → `{"code","expires_at"}`. The code is shown once and stored only as a hash |
| `GET /v1/admin/clients`, `GET /v1/admin/clients/{id}` | list / details with grants and credentials |
| `POST /v1/admin/clients/{id}/revoke` | revoke the client and every credential; tokens stop working immediately |
| `PUT /v1/admin/clients/{id}/grants/{device}` | `{"scopes":[…]}` replaces that device's scopes |
| `DELETE /v1/admin/clients/{id}/grants/{device}` | remove the grant |
| `GET /v1/admin/audit?limit=&before=` | newest first, paged (`next_before`) |

All bodies are JSON, max 64 KiB, unknown fields rejected. Errors: `{"error":{"code","message"}}`.

## Audit
Recorded: device registration/connection/failed login/revocation, pairing issue and redeem, every login success and
failure (with the internal reason), grant changes, client and credential revocation, and each command's dispatch,
denial and completion (capability and result code only). **Never recorded:** tokens, pairing codes, nonces, signatures,
public keys, command arguments or results. Detail fields come from an allow-list and values that look like secrets are
refused (tested).

**Fail closed:** issuing a pairing code, setting a grant and dispatching a command are written to the audit log
*first*; if that write fails the action is refused (`503 audit_unavailable`). **Revocations are the opposite:** they
always go through, and are logged on a best-effort basis, so a broken audit log can never stop you cutting off access.

Retention: `RELAY_AUDIT_RETENTION_DAYS` (default 90); expired events are purged hourly.

## Configuration (environment)
| Variable | Required | Meaning |
|---|---|---|
| `RELAY_DATABASE_URL` | yes | PostgreSQL URL. Migrations run at startup |
| `RELAY_ADMIN_TOKEN` | yes | bootstrap admin token, 32+ characters |
| `RELAY_PUBLIC_ORIGIN` | yes | e.g. `wss://relay.example.com` (no path, lower-cased). Devices and clients sign it |
| `RELAY_TLS_CERT_FILE`, `RELAY_TLS_KEY_FILE` | one of TLS / dev flag | serve TLS directly |
| `RELAY_ALLOW_INSECURE_HTTP` | no | `true` allows plain HTTP / `ws://` (development only) |
| `RELAY_LISTEN_ADDR` | no | default `:8443` |
| `RELAY_TOKEN_TTL_MINUTES` | no | client token lifetime, 1–60, default 10 |
| `RELAY_AUDIT_RETENTION_DAYS` | no | 1–3650, default 90 |

The relay refuses to start if any rule is violated and reports all problems at once.

## Limits and known gaps
* **Pairing approval is the administrator, not the phone.** The spec allows "another trusted administrative channel", and
  the phone still enforces its own policy (a capability must be switched on in the app). Asking the phone's owner to
  approve each new client is not built.
* **No role bundles.** Authorization is per-client scopes; there is no "operator"/"viewer" shortcut.
* Messages ≤ 64 KiB; handshake ≤ 10 s; device dropped after 75 s of silence; five protocol violations close a connection.
* Rate limits (per IP, in memory): 60 requests/min to the login and pairing endpoints, 10/min to redeem, 30 failed
  authentications/min, 20 challenges/min per client id. **Behind a reverse proxy every request has the proxy's address**,
  so the limits then apply to all clients together; `X-Forwarded-For` is deliberately not trusted.
* Tokens, challenges and rate-limit counters are in memory: **one relay instance only**. A restart logs every client out
  (they just log in again).
* A replayed HTTP request is a new command; there are no idempotency keys yet.
* TLS is required unless you set the development flag. No certificate pinning.

## Run locally
```bash
cp deploy/.env.example deploy/.env      # set POSTGRES_PASSWORD and RELAY_ADMIN_TOKEN (openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up --build
curl localhost:8443/healthz
```
Tests: `cd relay && go test -race ./...`. To include the PostgreSQL tests set `RELAY_TEST_DATABASE_URL` to a disposable
database; every test creates and drops its own schema, so packages can run in parallel.
