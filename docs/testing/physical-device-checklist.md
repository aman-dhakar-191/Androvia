# Physical-device test checklist (Phase 1)

CI emulators cannot show how OEM battery management behaves, so these steps are done by hand on real devices, from
more than one OEM, and the results are written down. Until a row is filled in, the behavior is **untested**.

Record: device model, OEM skin, Android version, build (`versionName`), date, tester.

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | Fresh install, open app | Device id shown; key protection level shown (not "unknown") | |
| 2 | Tap Start, grant notification permission | Notification appears; status "Running locally, no relay configured" | |
| 3 | Tap Start, deny notification permission | Runtime still starts; status "permission-limited"; entry visible in Task Manager | |
| 4 | Run self-test with capability off | `permission_denied` | |
| 5 | Enable `device.info`, run self-test | `result` with manufacturer/model/sdk_int matching the device | |
| 6 | Screen off 10 min, screen on | Service still running (status unchanged), self-test works | |
| 7 | Lock the device 30 min (Doze likely), unlock | Same as 6; note whether the service survived | |
| 8 | Swipe app from recents | Note whether the service survives (expected on stock Android: yes; OEMs vary) | |
| 9 | Force-stop from system settings | Service gone; reopening app shows "Stopped" (no stale "running") | |
| 10 | Reboot | Service not running; app shows "Stopped" (auto-start is not implemented) | |
| 11 | Notification "Stop" action | Service stops, status "Stopped" | |
| 12 | Start the service while the app is in background (e.g. `adb shell am start-foreground-service`) | Expected to be refused on Android 12+; app should show a start error and not crash | |
| 13 | Clear app data, reopen | New device id (key lost with data is not guaranteed on all devices — note behavior) | |
| 14 | Battery saver on, repeat 6 | Note result | |

Also record on each device: whether StrongBox was used, and any OEM "auto-start"/"battery optimization" setting
that changed the results.
