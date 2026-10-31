# ADR 0005 — Client identity, pairing and authorization (Phase 3)

Status: Accepted (implemented; not yet used with a real MCP client or a physical phone)
Date: 2026-10-31

## Context
Before Phase 3 one bootstrap token could register devices *and* send any command to any device. The spec (§6) asks for
independent per-client identities, asymmetric credentials instead of shared secrets, deny-by-default scopes enforced
at the relay and again on the phone, revocation, rotation, and an audit trail.

## Decisions
1. **Two planes, no shared credential.** The bootstrap admin token is demoted to the administrative channel (devices,
   pairing codes, grants, revocation, audit). It cannot send commands. Clients use their own keys. Compromise of one
   plane does not directly give the other, and an admin who wants access has to pair a client, which is audited.
2. **Clients hold their own EC P-256 key** (same primitives as the device: SPKI public key, ASN.1 DER ECDSA/SHA-256). The
   relay stores only public keys. Login is a signed challenge; the result is a short-lived opaque bearer token.
   *Why a token and not per-request signing:* MCP clients and most agent SDKs expect a bearer token (spec §9), and one
   signature per login keeps the key off the hot path. Tokens are in memory only and re-validated against the client
   and credential on every use, so revocation is immediate.
3. **Pairing codes, not open registration.** An administrator issues a single-use, 128-bit, time-limited code (15 min by
   default) that carries the grants. Only its hash is stored. Because redeeming needs a code, the unauthenticated
   endpoint cannot be used to flood the relay with pending clients, and approval is inherent in issuing the code.
   Every failure is the same `invalid_code`.
4. **Scopes are explicit, with no wildcards:** `devices:read` and `capability:<id>:execute`, granted per (client,
   device). One policy engine (`internal/policy`) decides; REST uses it now and the MCP gateway must use the same code
   (spec §9). A lookup failure is an error, never an allow.
5. **No existence oracle.** A device the client has no grant on answers exactly like a missing device. Failed logins are
   one generic 401 whatever the cause; challenges are issued to unknown clients too.
6. **Signatures are domain-separated and origin-bound:** `androvia/client-auth/v1\0 || nonce || client_id ||
   credential_id || relay origin`. The device handshake uses a different prefix, so a signature for one cannot be
   replayed as the other. The challenge is consumed before anything else is checked, so a failed attempt cannot be
   retried on the same nonce.
7. **Rotation = add a replacement key, then retire the old one.** Up to 5 active keys, 365-day lifetime, and the last usable
   key cannot be removed (no self lock-out). Re-pairing is a new code.
8. **Audit-first for privilege, audit-after for revocation.** Issuing a code, setting a grant and dispatching a command are
   recorded before they happen and refused if the record cannot be written. Revocations are never blocked by the audit
   log. Detail fields are allow-listed and secret-shaped values are refused, so a coding mistake cannot leak a token
   into the log.
9. **Rate limiting only where it matters now:** the unauthenticated endpoints and repeated failed authentication, per IP,
   in memory. General API rate limiting is Phase 7.

## Not done, on purpose
* **Approval on the phone.** The administrator's code is the approval. Showing "Allow client X to run device.info?" on the
  device needs a new message type and UI; it should be added before sensitive capabilities exist.
* **Role bundles** (spec §4 says "roles and scopes"): scopes only for now.
* Idempotency keys, per-client rate limits, multi-instance token storage.

## Consequences
* A pairing code is a bearer secret until redeemed: deliver it over a trusted channel and keep the lifetime short.
* The administrator's powers are large (they can pair a client and grant it anything); their actions are audited but
  not approved by anyone else.
* `RELAY_PUBLIC_ORIGIN` is now security-relevant for clients as well as devices: it must be identical on both ends.
