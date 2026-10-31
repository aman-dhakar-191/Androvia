# CLAUDE.md

Source of truth: `docs/ANDROVIA_SPEC.md`. Read it, and the ADRs in `docs/adr/`, before changing anything.

Rules (from spec §12):
- Work phase by phase. Only Phase 0 and Phase 1 (Android runtime foundation) are in scope until told otherwise.
- Never weaken authentication/authorization to make something work. Deny by default.
- Never commit secrets, keystores or signing material. Use ignored local config or environment variables.
- Every change needs tests, including denied/invalid/lifecycle cases for security-sensitive paths.
- Ask before changing agreed decisions (spec §4) or adding broader permissions or remote-control behavior.
- Keep docs and the README status table truthful: distinguish implemented, tested, partial and unimplemented.
- Do not add Redis, dashboard, SDKs or a broad capability catalog without justification.

Build verification: the Android SDK is not available in the cloud dev sandbox, so GitHub Actions is the build and test
oracle. Report CI results, not assumptions.
