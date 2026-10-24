CREATE TABLE IF NOT EXISTS email_verification_challenges (
    user_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    resend_after TIMESTAMPTZ NOT NULL,
    attempt_count SMALLINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    send_count SMALLINT NOT NULL DEFAULT 1 CHECK (send_count >= 0),
    window_started_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
