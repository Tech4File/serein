-- Queue retention is enforced by API startup cleanup. This index supports recipient drains.
CREATE INDEX IF NOT EXISTS queued_ciphertexts_created_at ON queued_ciphertexts(created_at);
