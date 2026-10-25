ALTER TABLE device_public_keys
    ADD COLUMN IF NOT EXISTS layer2_public_key JSONB;

ALTER TABLE device_public_keys
    DROP CONSTRAINT IF EXISTS device_public_keys_key_version_check;

ALTER TABLE device_public_keys
    ADD CONSTRAINT device_public_keys_key_version_check
    CHECK (key_version IN (1, 2));
