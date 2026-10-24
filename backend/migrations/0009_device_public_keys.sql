CREATE TABLE IF NOT EXISTS device_public_keys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    algorithm TEXT NOT NULL CHECK (algorithm = 'ECDH-P256'),
    public_key JSONB NOT NULL,
    fingerprint TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1 CHECK (key_version = 1),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_public_keys_by_user
    ON device_public_keys(user_id, registered_at);
