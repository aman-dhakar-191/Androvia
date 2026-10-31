# Androvia

A secure Android device runtime that exposes explicitly enabled device capabilities to authorized remote clients
through a self-hosted relay. See [`docs/ANDROVIA_SPEC.md`](docs/ANDROVIA_SPEC.md) for the full specification.

Androvia does not bypass Android's permission model, and it cannot promise uninterrupted background operation.

## Status

Foundation stage. **Nothing has been run on a physical device.** Verified state (GitHub Actions run on commit `a203d99`: unit tests, lint, assemble, instrumentation on API 29 and 34 all green) is below; "CI" means GitHub Actions
(`.github/workflows/android.yml`), because the Android SDK is not available in the author's dev sandbox.

| Area | Status |
|---|---|
| Phase 0 — design docs | Written (PR #1) |
| `core` (envelope parser, dispatcher, policy, replay guard, backoff, registry) | Implemented. 49 JVM unit tests pass locally; also run in CI |
| `capabilities` (`device.info`) | Implemented. 4 JVM unit tests pass locally |
| `authentication` (Keystore EC P-256 identity, signing) | Implemented. Instrumentation tests pass in CI on API 29 and 34 **emulators** (not physical devices) |
| `runtime` (Room, foreground service `specialUse`, DI) | Implemented. Room/policy/dispatch tests pass in CI on emulators; **service lifecycle (screen-off, locked, Doze, OEM) is untested** |
| `app` (Compose status screen) | Compiles, lints and assembles in CI. UI not exercised by any automated test |
| Relay (`relay/`: device WebSocket, registry, command routing, PostgreSQL, Docker Compose) | Implemented and tested in Go (race detector, real PostgreSQL). Docker image/Compose verified only by CI. See `docs/relay.md` |
| Android relay client (`android/api` + wiring in `runtime`/`app`: opt-in `wss://` connection while the runtime runs, handshake, heartbeat, reconnect, command routing to the local dispatcher) | Implemented. 14 JVM tests against a fake relay and 7 end-to-end tests against the real Go relay pass (CI job `Relay end-to-end`). The Android wiring compiles in CI; **never run on a physical device**. See ADR 0004 |
| Release signing + `release.yml` + store listing | Configured; **untested** until signing secrets exist and a tag is pushed. See `docs/distribution.md` |
| Client identity, pairing codes, signed login, per-device scopes, revocation, rotation, audit log (Phase 3) | Implemented in the relay and tested (Go, Kotlin against the real relay, and a curl/openssl walkthrough). **Pairing is approved by the administrator, not on the phone.** See `docs/relay.md`, ADR 0005 |
| MCP gateway (`/mcp`: two read-only tools, stateless, official Go SDK; protocol revisions 2024-11-05 to 2026-07-28) | Implemented and tested against the official Go and Python MCP SDK clients (CI job `MCP interop`). **Not tested with Claude Desktop/Code or other hosts; auth is Androvia's own token, not OAuth.** See `docs/mcp.md`, ADR 0006 |
| MCP stdio bridge (`cmd/mcpbridge`: pairs, holds the key, logs in and refreshes tokens, so hosts need no pasted token) | Implemented; Go tests plus the built binary driven by the official Python MCP SDK over stdio (CI job `MCP interop`). **Not tested with a real MCP host; no Windows key-permission check.** See `docs/mcp.md` |
| Dashboard, SDKs | Not started |

Limitations: the relay connection is opt-in and exists only while the runtime runs; no reboot auto-start; no
foreground-service restart after the process dies; no certificate pinning; the relay's administrator can pair clients without the phone's approval. See `docs/testing/physical-device-checklist.md`.

## Build and test

```bash
cd android
./gradlew :core:test :capabilities:test            # JVM tests
./gradlew lintDebug assembleDebug                   # needs Android SDK (platform 36)
./gradlew :authentication:connectedDebugAndroidTest :runtime:connectedDebugAndroidTest   # needs device/emulator
```

## Docs
- [Specification](docs/ANDROVIA_SPEC.md)
- [ADR 0001 — foreground service type](docs/adr/0001-foreground-service-type.md)
- [ADR 0002 — minimum SDK](docs/adr/0002-min-sdk.md)
- [ADR 0003 — device key algorithm](docs/adr/0003-device-key-algorithm.md)
- [Threat model](docs/threat-model.md)
- [Message envelope](docs/protocol/envelope.md)
- [Relay schema draft](docs/relay-schema-draft.md)
- [Physical-device checklist](docs/testing/physical-device-checklist.md)
- [Distribution via the private app store](docs/distribution.md)
- [Relay](docs/relay.md)
- [ADR 0004 — Android relay client](docs/adr/0004-android-relay-client.md)
- [ADR 0005 — client identity and authorization](docs/adr/0005-identity-and-authorization.md)
- [MCP gateway](docs/mcp.md) · [ADR 0006 — MCP gateway](docs/adr/0006-mcp-gateway.md)
- [Client login example](deploy/examples/client-login.sh) · [Python MCP client example](deploy/examples/mcp_client.py)
