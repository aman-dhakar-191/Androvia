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
| T14 | Stolen or leaked admin token | It cannot send commands; every use of it that changes state is audited; it is rate limited and never logged. It can still pair a new client and grant it access, so keep it secret and rotate it. *Phase 3.* |
| T15 | Replayed or stolen login exchange | The nonce is single-use, expires in 60 s, is bound to one client id, and is consumed before any check, so even a valid recorded exchange fails. Signatures bind the relay origin. Tokens are short-lived and die with their client or credential. *Phase 3, tested.* |
| T16 | Client reaches a device or capability it was not granted | Deny by default through one policy engine; scopes are per device and per capability with no wildcards; an ungranted device looks non-existent. The phone applies its own policy as well. *Phase 3, tested.* |
| T17 | Pairing code guessed, intercepted or reused | 128-bit random, single-use under concurrency, 15-minute default life, stored hashed, identical error for every failure, rate limited. A code is a secret until redeemed: send it over a trusted channel. *Phase 3.* |
| T18 | Audit log leaks secrets, or is down while privileged actions happen | Allow-listed fields, secret-shaped values refused, tests scan logs and the audit log for tokens/codes/keys. Issuing codes, granting and dispatching commands are refused when the audit write fails; revocation is never blocked. *Phase 3, tested.* |
| T19 | Malicious or compromised administrator | **Not mitigated.** There is no second approver and no approval on the phone yet. Actions are audited only. |
| T20 | A tool is callable that the owner never intended (tool poisoning, "everything the device can do") | Hard-coded allowlist of two read-only tools; names outside it are rejected; adding a tool needs code, schema, scope and tests. *Phase 4, tested.* |
| T21 | Identity or authority smuggled in through tool arguments (confused deputy) | Identity is read from the authenticated transport only; schemas forbid extra properties; the client's token is never passed on to the device or anyone else. *Phase 4, tested.* |
| T22 | Browser-based DNS rebinding against `/mcp` | `Origin` is validated against the relay's own origin; no wildcard CORS on `/mcp`; every request needs a bearer token a browser page cannot obtain. *Phase 4, tested.* |
| T23 | **Prompt injection through device-supplied text** returned to an agent | **Not mitigated.** Today's results are a model name and OS version. Results are structured data, but the agent decides how to treat them. Must be re-assessed before any capability returns user content. See `docs/mcp.md`. |
| T24 | An agent over-reaches (tries every device and capability) | Scopes are per device and per capability; an ungranted device looks non-existent; every call is audited with `channel: mcp`; failed authentication is rate limited. The agent cannot widen its own grants. *Phase 4.* |
| T25 | The bridge's private key is stolen from the user's disk, or read by another local user | Key file is mode `0600` and the bridge refuses to start if group/other can read it (POSIX); the key is created on the machine and never leaves it; a stolen key gives exactly that client's grants and is cut off by revoking the client. **Residual:** anything running as the same user can use the key, and the Windows permission check is not implemented. *Phase 4, tested on POSIX.* |

## Out of scope for now
Rooted/compromised OS, hardware attacks on the TEE, nation-state adversaries, relay hosting hardening (Phase 7).
