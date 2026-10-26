ALTER TABLE encrypted_transfer_device_envelopes
    ADD COLUMN IF NOT EXISTS crypto_version SMALLINT NOT NULL DEFAULT 1;
