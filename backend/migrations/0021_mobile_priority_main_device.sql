-- Mobile devices (iOS/Android) outrank browser sessions as the history authority.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'web';
DO $$ BEGIN
    ALTER TABLE devices ADD CONSTRAINT devices_platform_check CHECK (platform IN ('web','android','ios'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
UPDATE devices SET platform=CASE
    WHEN label ILIKE '%android%' THEN 'android'
    WHEN label ILIKE '%ios%' OR label ILIKE '%iphone%' OR label ILIKE '%ipad%' THEN 'ios'
    ELSE platform END
WHERE platform='web';

-- Initial selection prefers the oldest active mobile device, then the oldest active device.
UPDATE accounts a
SET main_device_id=(
    SELECT d.id FROM devices d
    WHERE d.user_id=a.id AND d.revoked_at IS NULL
    ORDER BY CASE WHEN d.platform IN ('android','ios') THEN 0 ELSE 1 END,d.created_at ASC,d.id ASC
    LIMIT 1
), main_device_designated=TRUE
WHERE NOT a.main_device_designated
  AND EXISTS (SELECT 1 FROM devices d WHERE d.user_id=a.id AND d.revoked_at IS NULL);

-- A designated, non-NULL authority is canonicalized to the oldest active mobile device.
-- Do not refill a NULL designation: that represents a main which was revoked/lost and requires explicit promotion.
UPDATE accounts a
SET main_device_id=(
    SELECT m.id FROM devices m
    WHERE m.user_id=a.id AND m.revoked_at IS NULL AND m.platform IN ('android','ios')
    ORDER BY m.created_at ASC,m.id ASC LIMIT 1
)
WHERE a.main_device_designated
  AND a.main_device_id IS NOT NULL
  AND EXISTS (SELECT 1 FROM devices m WHERE m.user_id=a.id AND m.revoked_at IS NULL AND m.platform IN ('android','ios'));

-- A main change/revocation invalidates pending ciphertext relays for the old pairing.
UPDATE history_sync_requests r
SET status='cancelled'
FROM accounts a
WHERE a.id=r.user_id
  AND r.status IN ('pending','transferring','ready')
  AND (r.main_device_id IS DISTINCT FROM a.main_device_id
       OR EXISTS (SELECT 1 FROM devices d WHERE d.id IN (r.main_device_id,r.child_device_id) AND d.revoked_at IS NOT NULL));

DELETE FROM history_sync_batches b
USING history_sync_requests r
WHERE b.request_id=r.id AND r.status='cancelled';
