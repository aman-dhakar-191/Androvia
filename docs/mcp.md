# MCP gateway (Phase 4)

AI agents reach a user's Android devices through the relay's **Model Context Protocol** endpoint:

```
https://<relay>/mcp        (Streamable HTTP, JSON responses, stateless)
```

It is built on the official Go MCP SDK and is an adapter over the same code REST uses (`internal/commands`): the same policy
engine, audit log and command routing. Design decisions: `docs/adr/0006-mcp-gateway.md`.

## Status
| | |
|---|---|
| Protocol revisions served | `2026-07-28` (stateless, `server/discover`), `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` (as reported by the server's own `server/discover`) |
| Tested with | the official **Go** SDK client (negotiates `2026-07-28`: all tool, grant, error and cancellation tests); the official **Python** SDK `mcp==2.3.0` client on `2025-11-25` (initialize handshake) and on `2026-07-28` (`discover`), in CI job `MCP interop`; and raw JSON-RPC against `2024-11-05`, `2025-03-26`, `2025-06-18` and `2025-11-25` (initialize, `tools/list`, `tools/call`) |
| **Not tested** | Claude Desktop / Claude Code, ChatGPT, Cursor, MCP Inspector, the TypeScript SDK. They should work if they can send an `Authorization` header, but that is unverified |
| Authorization | Androvia's own signed-challenge login (see below), **not OAuth** |
| Tools | two, both read-only (below) |
| Resources, prompts, `listChanged` notifications | not provided |

## Connecting
1. An administrator registers the phone, issues you a pairing code with the grants you need, and you pair and log in
   (`deploy/examples/client-login.sh`, or any code that follows `docs/relay.md` → "Login"). You get an access token.
2. Point your MCP client at `https://<relay>/mcp` and send `Authorization: Bearer <token>` on every request.
3. Example with the official Python SDK: `deploy/examples/mcp_client.py` (run `python mcp_client.py --discover` for the
   stateless 2026-07-28 path).

**Tokens are short-lived** (10 minutes by default, at most 60 via `RELAY_TOKEN_TTL_MINUTES`) and there is no refresh
token. A client that can only be given a fixed header must be given a fresh token before it expires. A small bridge that
holds your key and logs in by itself is planned but **not built**.

### Why not OAuth
MCP makes authorization optional, and its OAuth profile (authorization code with a human consent screen, discovery, client
registration) is designed for human-operated clients. Androvia clients are machines holding their own keys, and we do not
run an OAuth authorization server. The relay publishes RFC 9728 protected-resource metadata at
`/.well-known/oauth-protected-resource/mcp` (with `bearer_methods_supported: ["header"]` and **no**
`authorization_servers`), and answers an unauthenticated request with `401` and
`WWW-Authenticate: Bearer resource_metadata="…"`. A client that insists on running an OAuth flow will therefore fail
clearly instead of confusingly.

## Tools
Explicit allowlist; nothing is exposed because a device happens to support it. `tools/list` is sorted by name and shows
**only the tools this client could use** (it must hold the scope on at least one device); every call is authorised again.

| Tool | Needs | Arguments | Result (`structuredContent`) |
|---|---|---|---|
| `list_devices` | `devices:read` on a device | none | `{"devices":[{"device_id","label","status","online","last_seen_at"?}]}` — only devices the client may read |
| `get_device_info` | `capability:device.info:execute` on that device | `{"device_id": "<64 hex>"}` | `{"manufacturer","model","android_release","sdk_int","security_patch"?,"supported_abis"}` from the phone |

Both are annotated `readOnlyHint` and `idempotentHint`. Arguments are validated against the published JSON Schema; **unknown
properties are rejected**, so there is no way to pass a client id, a role or a token as an argument. A command sent over
MCP takes up to 15 s. If the client gives up first, the relay sends the phone a `cancel` (verified with the Go SDK client on `2026-07-28`; the SDK documents this behaviour only for that revision, so on older revisions an abandoned command may run until its timeout).

### Errors
Domain failures are **tool errors** (`isError: true`, text for the model, and `structuredContent`):
`{"error":{"code","message","source"?},"request_id"?}`. The codes are the REST codes:

| code | meaning |
|---|---|
| `device_not_found` | no such device **or** the client has no grant on it (indistinguishable on purpose) |
| `forbidden` | the client may see the device but not do that |
| `device_offline`, `device_disconnected`, `timeout` | the phone is not reachable / dropped / did not answer |
| `permission_denied` (with `"source":"device"`) | the phone's owner has not switched that capability on in the app |
| `device_revoked`, `invalid_request`, `audit_unavailable`, `internal` | as in REST |

Malformed JSON-RPC, an unknown tool name, or a failed authentication are protocol-level errors (HTTP status or JSON-RPC
error), as the specification prescribes.

## Security properties (each is covered by a test)
* **Identity comes from the transport**, never from arguments; the SDK validates arguments against schemas that forbid extras.
* **Deny by default**; a tool outside the allowlist is not callable; a revoked grant stops working on the next call, even
  inside an open client session.
* **Origin header validated** (DNS-rebinding defence): only the relay's own origin is accepted when an `Origin` is sent;
  non-browser clients send none and are unaffected. Request bodies are limited to 64 KiB.
* **Stateless**: no `Mcp-Session-Id`, no server-to-client stream (`GET`/`DELETE` → 405). There is no session to hijack and
  nothing carries state between two clients.
* **Failed authentication** is rate limited per IP (30/min) and audited; credentials never reach the logs or audit log.
* **Audit**: the same events as REST, tagged `channel: "mcp"`, written *before* a command is sent (no record, no command).

## Known gaps
* **The tool list does not know what is enabled on the phone.** It reflects the allowlist and the client's grants. The phone
  does not yet tell the relay which capabilities its owner switched on, so a tool can be listed and then answer
  `permission_denied` from the device. Closing this needs a new device→relay message and an Android change.
* **Content returned by a device is untrusted text** that an agent will read (today: model name, manufacturer). A
  tampered phone could try to instruct the agent (prompt injection). Today's data is low-risk; it matters much more once
  capabilities return user data (notifications, files). Treat tool results as data, never as instructions.
* One relay instance only; tokens and rate limits live in memory.
* Only two read-only tools. Nothing exposed over MCP can change the state of a phone.
