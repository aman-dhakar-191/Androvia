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
| Pairing and per-client authorization (Phase 3), MCP gateway, dashboard, SDKs | Not started. The relay currently uses one bootstrap admin token |

Limitations: the relay connection is opt-in and exists only while the runtime runs; no reboot auto-start; no
foreground-service restart after the process dies; no certificate pinning; one coarse admin token on the relay (Phase 3). See `docs/testing/physical-device-checklist.md`.

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
