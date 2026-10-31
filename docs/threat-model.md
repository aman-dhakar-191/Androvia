# Threat model (Phase 0 draft)

Scope: trust boundaries and top risks, to be refined as relay and identity work begins. Nothing below is implemented
unless the README status table says so.

## Assets
- Device private key (Keystore) and device identity.
- Data reachable through capabilities (device info now; notifications, files, location, camera, mic later).
- Client credentials and the policy/scope records on the relay.
- Audit log integrity.

## Actors
Device owner · authorized client · malicious/compromised client · network attacker · compromised relay · other app on the
device · someone with physical access to a locked device.

## Trust boundaries
1. Client ⇄ relay (HTTPS/MCP): relay trusts no client-supplied identity or scope.
2. Relay ⇄ device (WSS): device trusts relay only as a *router*; it re-validates every command.
3. App ⇄ Android OS: runtime permissions and special access are the OS's decision, not ours.
4. App process ⇄ other apps: no exported components that accept commands.

## Risks and mitigations

| # | Threat | Mitigation (planned unless noted) |
|---|---|---|
| T1 | Compromised relay sends commands the owner never authorized | Device-side deny-by-default policy and capability allowlist; high-impact capabilities need local user confirmation. *Phase 1: local policy check and allowlist are implemented in the dispatcher.* |
| T2 | Replay or delayed delivery of a captured command | `id` + `exp` + seen-ID cache; ≤60 s window. *Phase 1: dispatcher implements this.* |
| T3 | Device impersonation | Device ID = hash of Keystore public key; challenge-response on connect (Phase 3). |
| T4 | Stolen client credential | Per-client credentials, scopes, rotation, revocation, audit (Phase 3). |
| T5 | Malformed/oversized input crashes or exhausts the device | Size cap, strict schema validation, unknown-type rejection, per-command timeout. *Phase 1.* |
| T6 | Secrets leak via logs or audit | No tokens/keys in logs; payload retention minimised (all phases; reviewed in Phase 7). |
| T7 | Another app on the device invokes the runtime | No exported components beyond the launcher activity; service not exported. *Phase 1.* |
| T8 | Misleading status (claims connected/available when not) | Capabilities return `capability_unavailable`/`permission_required` truthfully; UI shows real state. |
| T9 | Locked-device signing abuse by code in the app process | Accepted tradeoff, see ADR 0003; sensitive capabilities add consent gates. |
| T10 | MCP bypasses REST authorization | MCP shares the same policy engine; identity from transport only (Phase 4). |
| T11 | Backup extraction of local DB/state | Exclude app data from cloud backup and device transfer (`allowBackup=false`). *Phase 1.* |
| T12 | Hostile or impersonated relay (e.g. a CA the user installed) | The relay can only trigger capabilities the user enabled on the device; every command passes the device dispatcher and local policy. The handshake signs the relay origin. **No certificate pinning (Phase 7)** and traffic is observable if TLS is intercepted. *Android client implemented; see ADR 0004.* |
| T13 | Two instances of one device fight for the relay slot | Relay replaces the old connection (`4001`); the client treats that as terminal instead of reconnecting. *Implemented and tested end to end.* |

## Out of scope for now
Rooted/compromised OS, hardware attacks on the TEE, nation-state adversaries, relay hosting hardening (Phase 7).
