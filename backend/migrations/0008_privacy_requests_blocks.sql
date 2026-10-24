-- Privacy-aware contact requests, per-account abuse throttling, and user blocking.
CREATE TABLE IF NOT EXISTS contact_requests (
    id UUID PRIMARY KEY,
    sender_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '30 days'),
    UNIQUE (sender_id, recipient_id),
    CHECK (sender_id <> recipient_id)
);
ALTER TABLE contact_requests
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '30 days');
CREATE INDEX IF NOT EXISTS contact_requests_incoming_expiry
    ON contact_requests (recipient_id, expires_at, created_at DESC);

CREATE TABLE IF NOT EXISTS account_action_limits (
    user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, action)
);

CREATE TABLE IF NOT EXISTS user_blocks (
    owner_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    blocked_user_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, blocked_user_id),
    CHECK (owner_id <> blocked_user_id)
);
