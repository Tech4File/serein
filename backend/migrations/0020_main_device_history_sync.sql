-- Main-device-only explicit history sync. Ciphertext is an expiring relay, never an archive.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS main_device_id UUID NULL REFERENCES devices(id) ON DELETE SET NULL;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS main_device_designated BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE accounts a SET main_device_id=(SELECT CASE WHEN first_device.revoked_at IS NULL THEN first_device.id ELSE NULL END FROM (SELECT d.id,d.revoked_at FROM devices d WHERE d.user_id=a.id ORDER BY d.created_at ASC,d.id ASC LIMIT 1) first_device),main_device_designated=TRUE WHERE NOT a.main_device_designated AND EXISTS(SELECT 1 FROM devices d WHERE d.user_id=a.id);

CREATE TABLE IF NOT EXISTS history_sync_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    main_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    child_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','transferring','ready','complete','cancelled','expired')),
    batch_count SMALLINT NULL CHECK (batch_count BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
    completed_at TIMESTAMPTZ NULL,
    CHECK (main_device_id <> child_device_id)
);
CREATE INDEX IF NOT EXISTS history_sync_requests_main_pending
    ON history_sync_requests(main_device_id, status, created_at);
CREATE INDEX IF NOT EXISTS history_sync_requests_child
    ON history_sync_requests(child_device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS history_sync_batches (
    request_id UUID NOT NULL REFERENCES history_sync_requests(id) ON DELETE CASCADE,
    batch_index SMALLINT NOT NULL CHECK (batch_index BETWEEN 0 AND 127),
    batch_count SMALLINT NOT NULL CHECK (batch_count BETWEEN 1 AND 128),
    ciphertext JSONB NOT NULL,
    digest TEXT NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    ciphertext_bytes INTEGER NOT NULL CHECK (ciphertext_bytes BETWEEN 1 AND 524288),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
    PRIMARY KEY (request_id, batch_index),
    CHECK (batch_index < batch_count)
);
CREATE INDEX IF NOT EXISTS history_sync_batches_expiry ON history_sync_batches(expires_at);
