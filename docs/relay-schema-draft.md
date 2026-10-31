# Relay database schema

The draft that used to be here is implemented. The authoritative schema is the numbered SQL in `relay/migrations/`:

* `0001_devices.sql` — `devices`
* `0002_clients_audit.sql` — `clients`, `client_credentials`, `grants`, `pairing_codes`, `audit_events`

Migrations are embedded in the relay binary and applied at startup under an advisory lock. Access tokens, login
challenges and rate-limit counters are deliberately **not** in the database (single relay instance; see `docs/relay.md`).
