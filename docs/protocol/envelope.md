# Message envelope (draft v1)

Status: draft for Phase 0. Phase 1 implements only local validation of this envelope (no network). Wire handshake,
heartbeat and reconnect are specified here but implemented in Phase 2/3.

All messages are UTF-8 JSON objects, max **65,536 bytes**. Unknown top-level fields and unknown `type` values are
rejected (`unsupported_message`), never ignored silently.

```json
{
  "v": 1,
  "type": "command",
  "id": "8f1c...uuid",
  "corr": "optional id of the message this answers",
  "device": "hex SHA-256 of device public key",
  "ts": "2026-10-31T12:00:00.000Z",
  "exp": "2026-10-31T12:00:30.000Z",
  "payload": { }
}
```

| Field | Rules |
|---|---|
| `v` | Integer protocol version. Receiver supports a set; unsupported → `unsupported_version`. |
| `type` | One of `hello`, `hello_ack`, `heartbeat`, `command`, `result`, `error`, `cancel`. |
| `id` | UUID, unique per sender. Receiver keeps seen IDs until `exp` to reject replays (`replayed`). |
| `corr` | Required on `result`, `error`, `cancel`; absent on `command`. |
| `device` | Target/source device ID. Must match the authenticated connection; never trusted by itself. |
| `ts`, `exp` | Required on `command`/`cancel`. `exp - ts` ≤ 60 s. Expired or future-dated beyond 30 s clock skew → `expired`. |
| `payload` | Typed per `type`; validated against a schema. |

## Command payload

```json
{ "capability": "device.info", "version": 1, "scopes_claimed": [], "args": { } }
```

`scopes_claimed` is informational only. **Authorization is never derived from message content**; the device checks
its own local policy (deny by default) and the relay checks server-side records.

## Result / error payload

`result`: `{ "status": "ok", "data": { } }`
`error`: `{ "code": "<stable_code>", "message": "human readable, no secrets" }`

Stable error codes: `malformed`, `unsupported_version`, `unsupported_message`, `too_large`, `expired`, `replayed`,
`unknown_capability`, `capability_unavailable`, `permission_required`, `permission_denied`, `invalid_args`,
`timeout`, `cancelled`, `rate_limited`, `internal`.

## Handshake (Phase 2/3, not implemented in Phase 1)

1. Device opens WSS, sends `hello` (versions supported, device ID, app version).
2. Relay replies `hello_ack` with a random 32-byte nonce and chosen version.
3. Device sends a signature (ECDSA P-256/SHA-256) over `nonce || device ID || relay origin`; relay verifies it
   against the stored public key and rejects unknown or revoked devices.
4. Heartbeat every 25 s; relay drops a connection after 3 missed beats. Device reconnects with bounded exponential
   backoff with jitter (base 1 s, cap 60 s, full jitter).
5. Short-lived session credential and renewal rules are decided in Phase 3.

## Cancellation and idempotency

`cancel` references the command by `corr`. Capabilities declare whether they are cancellable. Commands carry no
implicit retry; a retry is a new `id`. Capabilities that mutate state must declare idempotency before being added.
