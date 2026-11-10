-- Preserve bounded, metadata-only expiry outcomes after the queued ciphertext is purged.
ALTER TABLE message_receipts
    ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ NULL;

ALTER TABLE message_receipts
    DROP CONSTRAINT IF EXISTS message_receipts_terminal_state_check;
ALTER TABLE message_receipts
    ADD CONSTRAINT message_receipts_terminal_state_check
    CHECK (expired_at IS NULL OR delivered_at IS NULL);

CREATE INDEX IF NOT EXISTS message_receipts_expired_recipient_cursor
    ON message_receipts(recipient_user_id, recipient_device_id, expired_at, message_id)
    WHERE expired_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS message_receipts_expired_cleanup
    ON message_receipts(expired_at)
    WHERE expired_at IS NOT NULL;
