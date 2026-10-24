CREATE TABLE IF NOT EXISTS offline_messages (
    id UUID NOT NULL,
    room TEXT NOT NULL,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (room, recipient, id)
);
CREATE INDEX IF NOT EXISTS offline_messages_lookup ON offline_messages (room, recipient, created_at);
