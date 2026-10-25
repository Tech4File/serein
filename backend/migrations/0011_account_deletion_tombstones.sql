-- Preserve only the contact owner's chat-shell reference when the other account is deleted.
-- The account ID is an immutable, non-reused UUID; usernames/emails/passwords/keys are not retained.
-- Per-contact display labels are relationship metadata owned by the surviving contact.
ALTER TABLE contacts DROP CONSTRAINT IF EXISTS contacts_contact_id_fkey;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS contact_display_name TEXT;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
UPDATE contacts c
SET contact_display_name = a.display_name
FROM accounts a
WHERE a.id = c.contact_id AND c.contact_display_name IS NULL;
UPDATE contacts SET contact_display_name = 'Deleted User' WHERE contact_display_name IS NULL;
ALTER TABLE contacts ALTER COLUMN contact_display_name SET DEFAULT 'Deleted User';
ALTER TABLE contacts ALTER COLUMN contact_display_name SET NOT NULL;
CREATE INDEX IF NOT EXISTS contacts_by_deleted_peer ON contacts(owner_id, contact_id, deleted_at);
