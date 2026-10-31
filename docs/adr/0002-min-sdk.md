# ADR 0002 — Minimum SDK

Status: Accepted provisionally — `minSdk = 29`, to be confirmed by the first green CI build
Date: 2026-10-31

## Context

The spec proposes API 29 and asks for it to be validated. Targets: `compileSdk`/`targetSdk` 36.

## Evidence gathered

Verified from official docs:
- Room 2.8.0 raised its minSdk from 21 to 23 (<https://developer.android.com/jetpack/androidx/releases/room>).
- Android Keystore: StrongBox KeyMint exists on API 28+ devices that include it; `KeyGenParameterSpec.Builder
  .setIsStrongBoxBacked()` exists; `getSecurityLevel()` is the check for apps targeting API 29+;
  ECDSA P-256 is in the StrongBox subset (<https://developer.android.com/privacy-and-security/keystore>).
- Hilt and the Compose BOM pages state no minSdk above 29.

Not verified (docs fetch failed or was truncated):
- minSdk of the current Compose UI, AndroidX core and lifecycle artifacts.
- Ktor 3.x client engines (not used in Phase 1; revisit in Phase 2).
- API level of Keystore Ed25519 support, `setUserAuthenticationRequired` and `setUnlockedDeviceRequired`.
- Share of devices on API 29+. The Android dashboards page has no API-level table; use Play Console Reach data.

## Decision

Use `minSdk = 29` for Phase 1. Validation method: the Android Gradle plugin's manifest merger fails the build if any
dependency declares a higher minSdk, so a green CI `assembleDebug` / `lint` on the pinned dependency versions is the
check for the unverified AndroidX/Compose items. If it fails, raise minSdk and update this ADR rather than suppress it.

Because API-level coverage is unverified, **minSdk 29 is a compatibility target, not a tested claim** until CI is green
and at least one API 29–30 device or emulator has run the instrumentation tests.

## Consequences

- No Ed25519 in the key design (see ADR 0003).
- Code paths that need newer APIs must be guarded or avoided and tested.
