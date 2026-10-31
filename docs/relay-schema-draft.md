# Relay database schema (draft, PostgreSQL) — Phase 2/3

Draft only; migrations will be written in Phase 2. No Redis.

- `devices(id text pk /* hex sha256 of pubkey */, public_key bytea, label text, status text /* pending|active|revoked */, created_at, last_seen_at)`
- `clients(id uuid pk, label text, status text /* pending|active|revoked */, created_at)`
- `client_credentials(id uuid pk, client_id fk, public_key bytea null, secret_hash bytea null, expires_at, revoked_at, created_at)` — never store raw secrets.
- `grants(client_id fk, device_id fk, scope text, created_at, revoked_at, pk(client_id, device_id, scope))` — deny by default; separate read/execute/sensitive scopes.
- `pairing_requests(id uuid pk, kind text, code_hash bytea, device_id fk null, client_id fk null, expires_at, approved_at, approved_by text)`
- `audit_events(id bigserial pk, at timestamptz, actor_type text, actor_id text, device_id text null, action text, outcome text /* allowed|denied|error */, request_id uuid null, detail jsonb /* minimised, no secrets */)`

Indexes and retention policy are decided in Phase 2.
