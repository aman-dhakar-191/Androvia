# Androvia

A secure Android device runtime that exposes explicitly enabled device capabilities to authorized remote clients
through a self-hosted relay. See [`docs/ANDROVIA_SPEC.md`](docs/ANDROVIA_SPEC.md) for the full specification.

Androvia does not bypass Android's permission model, and it cannot promise uninterrupted background operation.

## Status

Planning / foundation stage. Nothing here has been validated on a device.

| Area | Status |
|---|---|
| Phase 0 — design docs (ADRs, threat model, envelope draft, schema draft) | Written, under review |
| Phase 1 — Android runtime foundation | Not started (separate PR) |
| Relay, identity/authorization, MCP gateway, dashboard, SDKs | Not started |

## Docs
- [Specification](docs/ANDROVIA_SPEC.md)
- [ADR 0001 — foreground service type](docs/adr/0001-foreground-service-type.md)
- [ADR 0002 — minimum SDK](docs/adr/0002-min-sdk.md)
- [ADR 0003 — device key algorithm](docs/adr/0003-device-key-algorithm.md)
- [Threat model](docs/threat-model.md)
- [Message envelope](docs/protocol/envelope.md)
- [Relay schema draft](docs/relay-schema-draft.md)
