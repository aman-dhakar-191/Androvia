# ADR 0003 — Device key algorithm and key storage

Status: Accepted
Date: 2026-10-31

## Context

Spec §6 prefers asymmetric challenge-response, with keys generated in Android Keystore and private keys never
uploaded. Ed25519 availability in Keystore by API level could not be confirmed from the docs we could fetch.

## Decision

- Device identity key: **EC P-256**, signatures **SHA256withECDSA**, generated with `KeyGenParameterSpec`
  (purpose `SIGN`, digest SHA-256), non-exportable.
- Try StrongBox first (`setIsStrongBoxBacked(true)` when `FEATURE_STRONGBOX_KEYSTORE` is present); on
  `StrongBoxUnavailableException` fall back to the default TEE-backed key. Record the resulting security level
  (via `KeyInfo.getSecurityLevel()`) in local state and surface it in the UI; never claim hardware backing without
  checking it.
- Do **not** require user authentication per signature: the runtime must be able to answer relay challenges while
  the device is locked (spec §2). This is a deliberate tradeoff — the private key is non-exportable, but any code
  running as the app can request signatures. Sensitive capabilities add their own user-consent gate.
- The stable device ID is the SHA-256 of the public key (SPKI DER), hex-encoded, so it cannot be claimed without
  possessing the key. A random installation UUID is kept only as a non-security label.
- Attestation (`setAttestationChallenge`) is deferred to the pairing phase (Phase 3).

## Consequences

- If the Keystore entry is lost (app data cleared, key invalidated), the device identity changes and must be re-paired.
- Ed25519 can be revisited once its minimum API level is verified.
