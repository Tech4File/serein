-- Keep a bounded relayed proof chain so long-offline peers can verify multiple rotations.
ALTER TABLE device_public_keys ADD COLUMN IF NOT EXISTS rotation_timestamp BIGINT NULL;

CREATE TABLE IF NOT EXISTS device_key_rotation_history (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_epoch BIGINT NOT NULL CHECK (key_epoch > 1),
    old_fingerprint TEXT NOT NULL,
    new_fingerprint TEXT NOT NULL,
    proof TEXT NOT NULL,
    rotation_timestamp BIGINT NOT NULL CHECK (rotation_timestamp > 0),
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, key_epoch),
    CHECK (old_fingerprint <> new_fingerprint)
);
CREATE INDEX IF NOT EXISTS device_key_rotation_history_lookup
    ON device_key_rotation_history(device_id, key_epoch DESC);
