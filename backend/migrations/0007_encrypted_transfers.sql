CREATE TABLE IF NOT EXISTS encrypted_transfers (
    id UUID PRIMARY KEY,
    sender_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    chunk_count INTEGER NOT NULL CHECK (chunk_count BETWEEN 1 AND 512),
    total_ciphertext_bytes BIGINT NOT NULL CHECK (total_ciphertext_bytes BETWEEN 1 AND 67108864),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    ready_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS encrypted_transfer_device_envelopes (
    transfer_id UUID NOT NULL REFERENCES encrypted_transfers(id) ON DELETE CASCADE,
    target_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    target_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    iv TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    acknowledged_at TIMESTAMPTZ NULL,
    PRIMARY KEY (transfer_id, target_device_id)
);

CREATE TABLE IF NOT EXISTS encrypted_transfer_chunks (
    transfer_id UUID NOT NULL REFERENCES encrypted_transfers(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    ciphertext BYTEA NOT NULL,
    sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (transfer_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS encrypted_transfers_sender_expiry
    ON encrypted_transfers (sender_user_id, expires_at);
CREATE INDEX IF NOT EXISTS encrypted_transfers_recipient_expiry
    ON encrypted_transfers (recipient_user_id, expires_at);
CREATE INDEX IF NOT EXISTS encrypted_transfers_expiry
    ON encrypted_transfers (expires_at);
CREATE INDEX IF NOT EXISTS encrypted_transfers_sender_device
    ON encrypted_transfers (sender_device_id, expires_at);
CREATE INDEX IF NOT EXISTS encrypted_transfer_envelopes_device
    ON encrypted_transfer_device_envelopes (target_device_id, transfer_id);
CREATE INDEX IF NOT EXISTS encrypted_transfer_chunks_by_transfer
    ON encrypted_transfer_chunks (transfer_id, chunk_index);
