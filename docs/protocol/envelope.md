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
| `type` | One of `hello`, `hello_ack`, `auth` (device → relay only, completes the handshake), `heartbeat`, `command`, `result`, `error`, `cancel`. |
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

## Handshake (implemented by the relay; the Android client is not built yet)

1. Device opens WSS and sends `hello` (`{"versions":[1],"app_version":"…"}`, `device` = its id).
2. Relay replies `hello_ack` (`{"nonce":"<base64, 32 random bytes>","version":1}`, `corr` = the hello id).
3. Device sends `auth` (`{"signature":"<base64 ASN.1 DER ECDSA P-256/SHA-256>"}`) over
   `"androvia/relay-auth/v1\0" || nonce || deviceID(64 ASCII hex) || relayOrigin` (e.g. `wss://relay.example.com`,
   no trailing slash). The relay verifies it against the registered key. Unknown, revoked and badly-signed devices
   are all closed with `1008 "authentication failed"`.
4. Device sends `heartbeat` every 25 s; the relay answers each one. The relay drops a device after 75 s of silence
   (close `4003`). Reconnect with bounded exponential backoff with equal jitter (base 1 s, cap 60 s; delay is in
   [ceiling/2, ceiling], never 0).
5. Short-lived session credentials and renewal are decided in Phase 3.

WebSocket close codes: `1008` auth/protocol failure, `1009` message too large, `4001` replaced by a newer connection,
`4002` device revoked, `4003` heartbeat timeout.

After authentication a device may send only `heartbeat`, `result` and `error`. Anything else gets an `error`
(`unsupported_message`); five violations close the connection. A message whose `device` differs from the
authenticated device closes it immediately. Relay `error` messages always carry a `corr` (a fresh id if there was
nothing to answer).

## Cancellation and idempotency

`cancel` references the command by `corr`. Capabilities declare whether they are cancellable. Commands carry no
implicit retry; a retry is a new `id`. Capabilities that mutate state must declare idempotency before being added.
