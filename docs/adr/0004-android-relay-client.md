# ADR 0004 — Android relay client

Status: Accepted (behavior on physical devices is untested)
Date: 2026-10-31

## Context
The relay (Phase 2) can route commands to an authenticated device, but the Android app could not connect to it.

## Decisions
1. **Ktor Client with the OkHttp engine** (spec §4). The protocol logic lives in plain-JVM modules (`core`, `api`) so it
   is unit-tested without a device; `:runtime` only wires it to Android.
2. **Opt-in, wss-only.** Nothing connects until the user enters a `wss://host[:port]` address *and* switches the relay on.
   `ws://` is refused in the app (it exists only as a test parameter). No path, query, credentials or fragment are accepted.
3. **Only while the foreground service runs.** The connection is owned by `RuntimeService`. Stopping the runtime closes it;
   there is no connection, and no way for the relay to reach the device, while the runtime is stopped. There is still no
   reboot auto-start (ADR 0001).
4. **The relay is only a transport.** Every `command` goes unchanged to the device's own dispatcher, which validates the
   envelope, target device, time window, replay, schema and the **local deny-by-default policy**. Enabling the relay
   enables no capability.
5. **Authentication has no explicit "ok" message**, so the device sends a heartbeat right after `auth` and treats the
   relay's answer as confirmation (state CONNECTED). Failure arrives as a close frame (`1008`).
6. **Reconnect rules.** Retryable: network loss, silence for 75 s (the relay answers every heartbeat, so silence means a
   half-open connection), authentication failure `1008` (the user may still be registering the device). Backoff is
   bounded exponential with equal jitter (1 s .. 60 s) and resets after a connection was confirmed.
   **Terminal (stop and show why):** `4001` replaced by a newer connection of the same device, `4002` device revoked.
   Retrying `4001` would make two instances of the same device fight for the slot.
7. **The origin is part of what is signed.** The device lower-cases the origin exactly as the relay normalises
   `RELAY_PUBLIC_ORIGIN`, so a phishing relay at another address cannot reuse a signature.
8. **Database migration, not reset.** `relay_config` is added by a Room migration 1→2; destructive fallback is deliberately
   not enabled because it would erase the user's capability choices (covered by an instrumentation test).

## Consequences / limits
* TLS trust is the system CA store; no certificate pinning. A user-installed or compromised CA could impersonate the relay.
  A relay that is impersonated still cannot make the device run anything the user has not enabled, but it could observe
  traffic. Pinning is a Phase 7 decision.
* The OkHttp engine does not support Ktor's `maxFrameSize`; the 64 KiB message limit is enforced when parsing, which means
  an oversized message from a hostile relay is buffered before it is rejected.
* Android may stop the service and its connection at any time (force-stop, OEM battery management, Doze, network change).
* The connection state is shown in the app; the notification text does not change with it.
