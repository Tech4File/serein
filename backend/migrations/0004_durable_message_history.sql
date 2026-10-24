-- Keep accepted ciphertext envelopes as history; delivery is a state transition, not deletion.
ALTER TABLE queued_ciphertexts
    ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS queued_ciphertexts_delivery
    ON queued_ciphertexts(recipient_device_id, delivered_at, created_at, id);

-- The API must apply this migration or its equivalent startup DDL before serving traffic.
