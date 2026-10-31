# Androvia — Product & Engineering Specification

> Source of truth for Claude Code and contributors implementing Androvia.
> Status: planning / foundation stage. This document describes intended behavior, not implemented or validated functionality.

## 1. Product overview

Androvia is a secure Android device runtime that exposes explicitly enabled device capabilities to authorized remote clients through a self-hosted relay. It is intended for ordinary applications, automation clients, and AI agents.

The Android device runs the Androvia app and maintains an outbound secure WebSocket (WSS) connection to a relay hosted on a self-managed VPS. Authorized clients connect to the relay using HTTPS APIs or the Model Context Protocol (MCP). The relay authenticates clients, enforces access policies, and routes approved requests to the registered Android device.

**Core principle:** Android is the execution node; the relay is the secure coordination and access-control layer. Androvia must never claim to bypass Android's permission model or platform security restrictions.

## 2. Product goals

- Expose selected Android capabilities to authorized remote clients.
- Support multiple registered clients, each with independent identity, permissions, and revocation.
- Support screen-off and locked-device operation where Android permits it.
- Provide a self-hosted relay without a third-party cloud control plane.
- Offer a stable HTTPS API and first-class MCP integration for AI agents.
- Make capability availability, permission requirements, and platform limitations visible.
- Make security, auditability, and least-privilege authorization foundational.

## 3. Non-goals and platform boundaries

- No rooting, custom ROM, or Android security bypass.
- No bypassing runtime permissions, scoped storage, background execution limits, or user-consent requirements.
- No promise of uninterrupted 24/7 execution. Force-stop, reboot, OEM battery management, Doze, network loss, and Android foreground-service policy can interrupt operation.
- No silent activation of sensitive capabilities. Camera, microphone, location, accessibility, notifications, and file access require clear disclosure and applicable Android permissions or special access.
- No unrestricted remote shell or arbitrary remote code execution by default.
- MCP is not an authorization mechanism. MCP requests must pass the same authentication and authorization checks as REST requests.

## 4. Agreed decisions

| Area | Decision |
|---|---|
| Android target | Android 16 / API 36 |
| Proposed minimum SDK | API 29 initially; validate before implementation |
| Android language and UI | Kotlin, Jetpack Compose |
| Android persistence / DI | Room / Hilt |
| Async and state | Kotlin coroutines and Flow |
| Android networking | Ktor Client |
| Device key storage | Android Keystore |
| Relay language | Go |
| Relay hosting | Self-hosted VPS |
| Relay database | PostgreSQL |
| Optional cache | Redis only if justified |
| Device-to-relay transport | Outbound secure WebSocket (WSS) |
| Client-to-relay transport | HTTPS |
| Agent integration | MCP over Streamable HTTP |
| Initial distribution | Private APK / private distribution |
| Client model | Multiple separately registered clients |
| Authorization | Per-client roles and fine-grained scopes, enforced by relay and device |

These are design decisions, not proof that the selected libraries or APIs have been validated. Re-check current Android 16 requirements before choosing foreground-service types or permissions.

## 5. Architecture

### Components

1. **Android application:** device identity and key management; runtime service and lifecycle; capability registry; local command dispatcher; device-side authorization; local persistence; Compose status UI.
2. **Relay service:** HTTPS API; WSS endpoint for Android devices; device and client registration; authentication, authorization, and revocation; command routing and response correlation; audit logging.
3. **MCP gateway:** MCP Streamable HTTP endpoint; exposes approved capabilities as tools and, where useful, resources/prompts; maps authenticated sessions to client identities; uses the same policy checks as REST.
4. **PostgreSQL:** device/client registrations, public keys and credential metadata, policies/scopes, pairing and revocation state, audit records.
5. **Optional dashboard:** device/client administration, pairing, permissions, revocation, audit, and operational status. It must use secured APIs, not a privileged bypass.

### Request flow

1. A client authenticates to the relay over HTTPS.
2. The relay resolves the client identity and verifies its status.
3. The relay checks permission for the requested device and capability.
4. The relay sends a correlated command to the Android device over its authenticated WSS connection.
5. Android independently validates the command, local policy, capability availability, and device state.
6. The capability executes only if permitted by Android and user configuration.
7. The device returns a structured result; the relay returns it to the client and records an audit event.

Never trust a client-supplied identity, device ID, scope, or authorization claim without validating it against server-side records.

## 6. Security model

Security is a core requirement, not a later add-on.

### Identity and pairing

- Give each Android installation a stable device identity.
- Generate device key material using Android Keystore where supported.
- Prefer asymmetric challenge-response over long-lived shared secrets.
- Register clients independently, each with its own identity and credentials.
- Require explicit user approval during pairing through the Android device or another trusted administrative channel.
- Store public keys and credential metadata on the relay; never upload private keys.
- Support credential rotation, client/device revocation, and re-pairing.

### Authorization

- Deny by default.
- Associate explicit scopes with a client and target device.
- Separate read, execute, and sensitive-operation permissions.
- Enforce policy at the relay and again on Android.
- Require stronger policy or user confirmation for high-impact actions.
- Keep capability-level checks close to each capability implementation.
- MCP and REST must share the same policy engine.

### Transport and command integrity

- Require TLS for HTTPS and WSS.
- Authenticate Android devices when they connect.
- Use short-lived tokens or signed requests as appropriate; define expiry, renewal, and revocation.
- Use request IDs, timestamps, expiry windows, and replay protection.
- Validate message size, schema, rate, and command type.
- Never log tokens, private key material, or secrets.
- Define timeouts, cancellation, retry behavior, and idempotency.

### Auditability

Record pairing, authentication failures, permission changes, revocation, command dispatch/completion, and denied actions. Minimize sensitive payload retention and document retention controls.

## 7. Android runtime

### Lifecycle

- Use a foreground service only with a valid, accurately declared foreground-service type and user-visible notification.
- Never misuse `dataSync`, `systemExempted`, or another service type to evade platform policy.
- Handle startup, shutdown, reboot behavior, network changes, relay reconnects, and process recreation explicitly.
- Use bounded exponential backoff with jitter for reconnects.
- Expose states such as connected, reconnecting, offline, permission-limited, and stopped.
- Explain that force-stop, OEM restrictions, Doze, and policy changes can interrupt availability.
- Test screen-off and locked-device behavior on physical devices from multiple OEMs.

### Capability interface

Each capability must declare:
- Stable identifier and version; description.
- Required Android permissions and special access.
- Whether user interaction or foreground UI is required.
- Availability on the current device and OS version.
- Authorization scopes; input/output schemas.
- Execution constraints, timeout, and cancellation behavior.

Potential modules (not all part of the first milestone):
- Device information and runtime status.
- Installed-app metadata, subject to package-visibility rules.
- Notifications, subject to notification-listener access and user consent.
- Accessibility operations, only through a transparently enabled accessibility service and in compliance with platform policies.
- Files, subject to scoped storage and user-granted access.
- Camera and microphone, subject to runtime permissions and background-use restrictions.
- Location, subject to runtime and background-location permissions.
- Connectivity and network status.
- System events available to ordinary applications.

A capability must report unavailable or permission-required rather than pretending an operation succeeded.

### First Android milestone

Implement only:
- Kotlin app targeting API 36.
- Compose status/dashboard screen.
- Runtime service and lifecycle handling, using a valid service type.
- Device identity creation and Keystore integration.
- Room persistence for local configuration and runtime state.
- Capability interface and registry.
- One low-risk device-information capability.
- Local command dispatcher with schema validation.
- Unit and instrumentation tests.

Do not implement the full capability catalog or connect the relay in this milestone. Establish and test the local runtime boundary first.

## 8. Relay and API design

Suggested Go package boundaries:
- `cmd/` — executable entry points.
- `internal/auth/` — authentication and credential validation.
- `internal/devices/` — device registration and lifecycle.
- `internal/clients/` — client registration and pairing.
- `internal/policy/` — scopes and authorization.
- `internal/connections/` — device WebSocket sessions.
- `internal/router/` — command dispatch and correlation.
- `internal/audit/` — security and operational events.
- `internal/mcp/` — MCP gateway and adapters.
- `internal/config/` — validated configuration.

Keep transport handlers thin; put business rules in testable service layers. Version public APIs, validate requests at boundaries, use stable error codes, and document authentication, scopes, rate limits, timeouts, and error behavior. Never expose an unauthenticated device WebSocket or arbitrary message injection.

### Device WebSocket protocol

Define a versioned, typed envelope with protocol version, message type, request/correlation ID, device identity, timestamps/expiry where applicable, and typed payload. Specify handshake, heartbeat, reconnect, command, result, error, cancellation, and protocol-version negotiation. Reject malformed or unknown message types safely.

## 9. MCP integration

- Follow the current official MCP specification and Streamable HTTP transport.
- Expose only capabilities enabled on the device and authorized for the requesting client.
- Derive identity from the authenticated transport/session, never from tool arguments.
- Validate tool arguments against declared schemas.
- Return structured errors for unsupported, unavailable, permission-denied, expired, or timed-out operations.
- Maintain an explicit tool allowlist; do not expose every device function automatically.
- Share policy, audit, and command-routing layers with REST.
- Add protocol-conformance and end-to-end tests.

## 10. Target repository layout

This is a target layout, not a requirement to create every directory immediately.

```text
Androvia/
├── android/
│   ├── app/
│   ├── core/
│   ├── runtime/
│   ├── authentication/
│   ├── authorization/
│   ├── capabilities/
│   └── api/
├── relay/
│   ├── cmd/
│   └── internal/
├── dashboard/
├── sdk/
│   ├── typescript/
│   └── python/
├── deploy/
├── docs/
├── .github/workflows/
├── .gitignore
├── CLAUDE.md
└── README.md
```

Create directories when implementation begins; avoid empty placeholder trees.

## 11. Implementation roadmap

### Phase 0 — Design validation
- Review this specification for feasibility.
- Verify Android 16 foreground-service and background-execution requirements.
- Define threat model, trust boundaries, message envelopes, and initial database schema.
- Record open questions and decisions as architecture decision records (ADRs).

### Phase 1 — Android runtime foundation
- Implement the first Android milestone in section 7.
- Add automated tests and a physical-device test checklist.
- No relay or remote command execution yet.

### Phase 2 — Relay foundation
- Go service, PostgreSQL migrations, device registration, WSS lifecycle, heartbeat, command routing, and local Docker Compose.
- Add relay unit and integration tests.

### Phase 3 — Identity and authorization
- Pairing, device/client credentials, signed challenge-response, scopes, policy enforcement, revocation, and audit.
- Test unauthorized clients, replayed commands, revoked credentials, and cross-device access.

### Phase 4 — MCP gateway
- Streamable HTTP MCP endpoint, explicit tool registration, policy-aware dispatch, protocol and end-to-end tests.

### Phase 5 — Capability expansion
- Add capabilities individually, each with permission declarations, constraints, tests, and documentation.
- Prioritize low-risk capabilities before sensitive ones.

### Phase 6 — Dashboard and SDKs
- Device/client administration and audit views.
- TypeScript and Python SDKs after the API contract stabilizes.

### Phase 7 — Hardening and distribution
- Threat-model review, dependency and secret scanning, rate limiting, observability, backup/restore, and security testing.
- CI for Android, Go, and dashboard.
- Signed APK release process with signing material outside source control.
- Private distribution and upgrade/rollback documentation.

## 12. Instructions for Claude Code

1. **Inspect before changing:** read the repository, build files, and documentation first.
2. **Plan each phase:** present a concise plan and identify assumptions before substantial changes.
3. **Work incrementally:** start with Phase 0 review and Phase 1 only; do not build the entire system at once.
4. **Verify platform behavior:** use current official Android documentation for APIs, permissions, and foreground-service rules.
5. **Preserve security boundaries:** never weaken authentication or authorization to make a demo work.
6. **Protect secrets:** use ignored local configuration or environment variables; commit safe placeholders only.
7. **Test every change:** cover normal behavior, denied behavior, invalid input, lifecycle failures, and relevant edge cases.
8. **Keep docs current:** update setup, API contracts, architecture decisions, and known limitations.
9. **Report honestly:** distinguish implemented, tested, partially working, and unimplemented features. Include exact test commands and results.
10. **Avoid premature complexity:** do not add Redis, dashboard, SDKs, or a broad capability catalog until justified.
11. **Do not promise guaranteed background availability:** document and test actual behavior on supported devices.
12. **Ask before changing agreed product decisions** or introducing broader permissions or remote-control behavior.

## 13. Definition of done

A milestone is complete only when acceptance criteria are documented, the project builds from a clean checkout, relevant tests pass, security-sensitive paths have negative tests, permissions and user-visible behavior are documented, platform limitations are recorded, no secrets are committed, and documentation reflects actual implementation status.

## 14. Starting instruction

Start with **Phase 0 review, then Phase 1 Android runtime foundation only**. Inspect the repository and propose a concise task breakdown before coding. Do not start the relay, MCP gateway, dashboard, SDKs, or advanced capabilities until the Android runtime foundation is implemented and tested.
