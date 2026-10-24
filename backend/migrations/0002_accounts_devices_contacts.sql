CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS devices_by_user ON devices(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_by_user ON auth_sessions(user_id, expires_at);
CREATE TABLE IF NOT EXISTS contacts (
    owner_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    contact_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(owner_id, contact_id),
    CHECK(owner_id <> contact_id)
);
CREATE TABLE IF NOT EXISTS queued_ciphertexts (
    id UUID NOT NULL,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY(recipient_device_id, id)
);
CREATE INDEX IF NOT EXISTS queued_ciphertexts_lookup ON queued_ciphertexts(recipient_device_id, created_at);
