# ADR 0001 — Foreground service type for the Androvia runtime

Status: Accepted (provisional until verified on physical devices)
Date: 2026-10-31

## Context

The runtime must keep a long-lived outbound connection and a command dispatcher alive while the app is in the
background. Since Android 14 (API 34) every foreground service must declare a type and hold the matching
`FOREGROUND_SERVICE_*` permission. The spec (§7) forbids choosing a type only to evade platform policy.

Facts taken from the official docs (fetched 2026-10-31):

- `dataSync` and `mediaProcessing` foreground services are limited to a total of **6 hours per 24 hours** for apps
  targeting Android 15+; the system then calls `Service.onTimeout()` and the service must stop within seconds or the
  app crashes with `RemoteServiceException`. Once exhausted, it cannot be restarted from the background.
  (<https://developer.android.com/develop/background-work/services/fgs/timeout>)
- `dataSync` may not be launched from a `BOOT_COMPLETED` receiver on apps targeting Android 15+.
  (<https://developer.android.com/develop/background-work/services/fgs/service-types>)
- Apps targeting 12+ cannot start a foreground service from the background except in listed cases (e.g. transition
  from a visible activity, battery optimizations disabled by the user).
  (<https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start>)
- `POST_NOTIFICATIONS` is not required to start a foreground service, but a notification is still mandatory; if the
  permission is denied the notification is hidden from the shade and appears only in the Task Manager.
  (<https://developer.android.com/develop/ui/views/notifications/notification-permission>)
- Per the same service-types page, `specialUse` requires `FOREGROUND_SERVICE_SPECIAL_USE` and a
  `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` property; values are free-form and reviewed on Google Play submission.
  *(This `specialUse` detail came from a tool-generated summary of the page, not verbatim text.)*

## Decision

Declare the runtime service as `android:foregroundServiceType="specialUse"` with a
`PROPERTY_SPECIAL_USE_FGS_SUBTYPE` value that honestly describes it ("User-enabled remote device runtime: maintains
an authenticated connection to a user-owned relay to execute explicitly enabled, user-authorized device capabilities").

Rejected:
- `dataSync` — the 6h/24h cap makes it unfit for a persistent runtime, and using it would misdescribe the service.
- `systemExempted`, `connectedDevice`, `remoteMessaging`, `mediaPlayback` — none accurately describe the service
  (spec §7 forbids misuse).

## Consequences

- Play Store distribution would require a Play Console declaration and review. Initial distribution is a private
  APK (spec §4), so this is deferred, but the justification text must stay accurate.
- The service must be started from a user-visible state (activity or user action). Automatic start after reboot is
  **not** assumed to work and is out of scope for Phase 1; it must be designed and tested separately.
- The service still can be killed by force-stop, OEM battery management, or Doze. Status UI must say so.
- If a future capability uses camera, microphone or location, it needs its own additional type and permissions, and
  cannot be started from the background (while-in-use restriction).

## Open items

- Verify on Android 16 hardware that a `specialUse` service survives screen-off for the expected duration.
- Re-check the type list and rules against the Android 16 behavior-changes pages before each release.
  Not verified in this ADR: the full Android 15/16 `BOOT_COMPLETED` restriction list.
