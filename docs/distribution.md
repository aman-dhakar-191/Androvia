# Distribution through the private app store

Androvia is distributed as a signed APK attached to a GitHub release and listed in
[`private-app-store`](https://github.com/aman-dhakar-191/private-app-store)'s `catalog.json`
(package `dev.androvia.app`, repo `aman-dhakar-191/Androvia`).

## Store rules this repo must satisfy
1. The repo is **public**. (If this repo is private the store cannot see its releases; check before first release.)
2. Each version is a normal (non-draft, non-prerelease) GitHub release with one `.apk` attached.
3. The tag matches `versionName` (`v0.1.0` → `0.1.0`).
4. `versionCode` always increases (the workflow uses the run number).
5. Every release is signed with the same key.

## One-time setup: signing key
Create a keystore once and keep it (and its passwords) somewhere safe outside the repo. Losing it means users must
uninstall and reinstall. You can reuse the key from `private-app-store`.

```bash
keytool -genkeypair -v -keystore androvia-release.jks -alias androvia -keyalg RSA -keysize 4096 -validity 10000
base64 -w0 androvia-release.jks   # value for KEYSTORE_BASE64
```

Add these repository secrets (Settings → Secrets and variables → Actions):
`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`.
Optional: `STORE_DISPATCH_TOKEN` (fine-grained token, `private-app-store` only, Contents: read/write) to make the
store show a release immediately. Never commit the keystore or passwords (`*.jks` is git-ignored).

## Releasing
```bash
git tag v0.1.0 && git push origin v0.1.0
```
The Release workflow refuses to run without the four signing secrets, runs the JVM unit tests, builds the signed APK,
and publishes the release.

## Status
Not yet exercised: no release has been made and the secrets are not configured, so the signed-release path
(`release.yml`) is **untested**. CI only checks that an unsigned release build assembles.
Also note the first install requires allowing "install unknown apps" for the store, and a `specialUse` foreground
service is fine for sideloaded distribution but would need a Play Console declaration for Google Play.
