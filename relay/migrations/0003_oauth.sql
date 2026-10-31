-- Phase 4b: OAuth 2.1 authorization server for remote MCP hosts (see docs/adr/0007-oauth.md).
-- Registered OAuth applications (Dynamic Client Registration). Public clients only: there is no secret to store.
CREATE TABLE oauth_clients (
    id            text        PRIMARY KEY CHECK (char_length(id) = 32),
    name          text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    redirect_uris jsonb       NOT NULL,
    created_at    timestamptz NOT NULL
);

-- Rotating refresh tokens. Only a hash is stored. Each token works once; presenting a used one revokes its whole family.
-- subject_client_id is the Androvia client (with its grants) that was created when the owner approved the connection.
CREATE TABLE oauth_refresh_tokens (
    token_hash        bytea       PRIMARY KEY,
    family_id         text        NOT NULL,
    oauth_client_id   text        NOT NULL REFERENCES oauth_clients (id),
    subject_client_id uuid        NOT NULL REFERENCES clients (id),
    resource          text        NOT NULL,
    created_at        timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    family_expires_at timestamptz NOT NULL,
    used_at           timestamptz
);
CREATE INDEX oauth_refresh_family_idx ON oauth_refresh_tokens (family_id);
CREATE INDEX oauth_refresh_subject_idx ON oauth_refresh_tokens (subject_client_id);
