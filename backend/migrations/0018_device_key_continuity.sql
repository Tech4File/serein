-- Device signing anchors allow ECDH bundle replacement only with a signed continuity chain.
ALTER TABLE device_public_keys
    ADD COLUMN IF NOT EXISTS signing_public_key JSONB NULL,
    ADD COLUMN IF NOT EXISTS key_epoch BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS previous_fingerprint TEXT NULL,
    ADD COLUMN IF NOT EXISTS rotation_proof TEXT NULL,
    ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ NULL;

ALTER TABLE device_public_keys
    DROP CONSTRAINT IF EXISTS device_public_keys_key_epoch_check;
ALTER TABLE device_public_keys
    ADD CONSTRAINT device_public_keys_key_epoch_check CHECK (key_epoch >= 1);
