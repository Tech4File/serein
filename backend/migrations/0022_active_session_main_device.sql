-- Main-device election, priority, and explicit promotion use the same eligibility rule
-- as active device/session APIs: non-revoked and at least one unexpired auth session.
-- A NULL designated main remains NULL; lost/revoked mains never silently fail over.
UPDATE accounts a
SET main_device_id=(
    SELECT d.id FROM devices d
    WHERE d.user_id=a.id
      AND d.revoked_at IS NULL
      AND EXISTS (
          SELECT 1 FROM auth_sessions s
          WHERE s.device_id=d.id AND s.user_id=d.user_id AND s.expires_at>now()
      )
    ORDER BY CASE WHEN d.platform IN ('android','ios') THEN 0 ELSE 1 END,
             d.created_at ASC,d.id ASC
    LIMIT 1
), main_device_designated=TRUE
WHERE NOT a.main_device_designated
  AND EXISTS (
      SELECT 1 FROM devices d
      WHERE d.user_id=a.id AND d.revoked_at IS NULL
        AND EXISTS (
            SELECT 1 FROM auth_sessions s
            WHERE s.device_id=d.id AND s.user_id=d.user_id AND s.expires_at>now()
        )
  );

-- Keep a designated authority while it is active, but canonicalize it to the oldest
-- active mobile whenever one exists. If the current authority has no unexpired
-- session, choose the oldest active device (mobile first). A NULL main is deliberately
-- excluded so a revoked/lost main still requires explicit promotion.
UPDATE accounts a
SET main_device_id=(
    SELECT d.id FROM devices d
    WHERE d.user_id=a.id
      AND d.revoked_at IS NULL
      AND EXISTS (
          SELECT 1 FROM auth_sessions s
          WHERE s.device_id=d.id AND s.user_id=d.user_id AND s.expires_at>now()
      )
    ORDER BY CASE WHEN d.platform IN ('android','ios') THEN 0 ELSE 1 END,
             d.created_at ASC,d.id ASC
    LIMIT 1
)
WHERE a.main_device_designated
  AND a.main_device_id IS NOT NULL
  AND EXISTS (
      SELECT 1 FROM devices d
      WHERE d.user_id=a.id AND d.revoked_at IS NULL
        AND EXISTS (
            SELECT 1 FROM auth_sessions s
            WHERE s.device_id=d.id AND s.user_id=d.user_id AND s.expires_at>now()
        )
  )
  AND (
      EXISTS (
          SELECT 1 FROM devices m
          WHERE m.user_id=a.id AND m.revoked_at IS NULL AND m.platform IN ('android','ios')
            AND EXISTS (
                SELECT 1 FROM auth_sessions s
                WHERE s.device_id=m.id AND s.user_id=m.user_id AND s.expires_at>now()
            )
      )
      OR NOT EXISTS (
          SELECT 1 FROM auth_sessions s
          JOIN devices current_main ON current_main.id=s.device_id
          WHERE current_main.id=a.main_device_id AND current_main.user_id=a.id
            AND current_main.revoked_at IS NULL AND s.user_id=a.id AND s.expires_at>now()
      )
  );

-- Cancel any pending relays whose authority changed or whose endpoints were revoked.
UPDATE history_sync_requests r
SET status='cancelled'
FROM accounts a
WHERE a.id=r.user_id
  AND r.status IN ('pending','transferring','ready')
  AND (r.main_device_id IS DISTINCT FROM a.main_device_id
       OR EXISTS (
           SELECT 1 FROM devices d
           WHERE d.id IN (r.main_device_id,r.child_device_id) AND d.revoked_at IS NOT NULL
       ));
DELETE FROM history_sync_batches b
USING history_sync_requests r
WHERE b.request_id=r.id AND r.status='cancelled';
