ALTER TABLE encrypted_transfers
    ADD COLUMN IF NOT EXISTS chunk_crypto_version SMALLINT NOT NULL DEFAULT 1;

ALTER TABLE encrypted_transfers
    DROP CONSTRAINT IF EXISTS encrypted_transfers_chunk_crypto_version_check;

ALTER TABLE encrypted_transfers
    ADD CONSTRAINT encrypted_transfers_chunk_crypto_version_check
    CHECK (chunk_crypto_version IN (1, 2));
