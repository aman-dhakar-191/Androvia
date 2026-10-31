-- Phase 2: device registry. Pairing/approval states, clients, grants and audit arrive in Phase 3.
CREATE TABLE devices (
    id           text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
    label        text        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    public_key   bytea       NOT NULL,
    status       text        NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz
);
