ALTER TABLE device_public_keys
    ADD COLUMN IF NOT EXISTS ratchet_version SMALLINT NOT NULL DEFAULT 2;

ALTER TABLE device_public_keys
    DROP CONSTRAINT IF EXISTS device_public_keys_ratchet_version_check;

ALTER TABLE device_public_keys
    ADD CONSTRAINT device_public_keys_ratchet_version_check
    CHECK (ratchet_version IN (2, 3));
