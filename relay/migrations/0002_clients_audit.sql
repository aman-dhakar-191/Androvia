-- Phase 3: client identities, credentials, per-device scope grants, single-use pairing codes, audit log.
CREATE TABLE clients (
    id         uuid        PRIMARY KEY,
    label      text        NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    status     text        NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE TABLE client_credentials (
    id         uuid        PRIMARY KEY,
    client_id  uuid        NOT NULL REFERENCES clients (id),
    public_key bytea       NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX client_credentials_client_idx ON client_credentials (client_id);

-- One row per (client, device, scope). No row means no access (deny by default).
CREATE TABLE grants (
    client_id  uuid        NOT NULL REFERENCES clients (id),
    device_id  text        NOT NULL REFERENCES devices (id),
    scope      text        NOT NULL CHECK (char_length(scope) <= 160),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, device_id, scope)
);

-- Only a hash of the code is stored. A code works once, until expires_at.
CREATE TABLE pairing_codes (
    id          uuid        PRIMARY KEY,
    code_hash   bytea       NOT NULL UNIQUE,
    grants      jsonb       NOT NULL,
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    redeemed_at timestamptz,
    redeemed_by uuid REFERENCES clients (id)
);

CREATE TABLE audit_events (
    id         bigserial   PRIMARY KEY,
    at         timestamptz NOT NULL,
    actor_type text        NOT NULL,
    actor_id   text        NOT NULL,
    device_id  text        NOT NULL,
    action     text        NOT NULL,
    outcome    text        NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error', 'info')),
    request_id text        NOT NULL,
    detail     jsonb       NOT NULL
);
CREATE INDEX audit_events_at_idx ON audit_events (at);
