CREATE TABLE IF NOT EXISTS message_deletion_tombstones (
    message_id UUID NOT NULL,
    target_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    actor_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sender_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    scope TEXT NOT NULL CHECK(scope IN ('me','everyone')),
    transfer_ids UUID[] NOT NULL DEFAULT '{}',
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now()+interval '90 days',
    PRIMARY KEY(message_id,target_user_id),
    CHECK(target_user_id=sender_user_id OR target_user_id=recipient_user_id)
);
CREATE INDEX IF NOT EXISTS message_deletion_tombstones_target_cursor
    ON message_deletion_tombstones(target_user_id,deleted_at,message_id);
CREATE INDEX IF NOT EXISTS message_deletion_tombstones_expiry
    ON message_deletion_tombstones(expires_at);
