CREATE TABLE IF NOT EXISTS message_receipts (
    message_id UUID NOT NULL,
    sender_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ NULL,
    read_at TIMESTAMPTZ NULL,
    PRIMARY KEY (message_id, recipient_device_id),
    CHECK (read_at IS NULL OR delivered_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS message_receipts_sender_message ON message_receipts(sender_user_id, message_id);
CREATE INDEX IF NOT EXISTS message_receipts_recipient_message ON message_receipts(recipient_user_id, message_id);

INSERT INTO message_receipts(message_id,sender_user_id,sender_device_id,recipient_user_id,recipient_device_id,accepted_at,delivered_at)
SELECT q.id,sd.user_id,q.sender_device_id,rd.user_id,q.recipient_device_id,q.created_at,q.delivered_at
FROM queued_ciphertexts q JOIN devices sd ON sd.id=q.sender_device_id JOIN devices rd ON rd.id=q.recipient_device_id
ON CONFLICT(message_id,recipient_device_id) DO NOTHING;
