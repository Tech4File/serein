-- Replace the optional deployment-wide KEK requirement with automatically provisioned
-- random per-account key bytes. Legacy KEK-wrapped rows (at_rest_version = 1) are
-- deliberately retained and must never be overwritten without their original KEK.
CREATE TABLE IF NOT EXISTS account_backup_keys (
    user_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    key_version SMALLINT NOT NULL DEFAULT 1 CHECK (key_version = 1),
    at_rest_version SMALLINT NOT NULL DEFAULT 2 CHECK (at_rest_version IN (1, 2)),
    key_material BYTEA NULL,
    nonce BYTEA NULL,
    ciphertext BYTEA NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE account_backup_keys ADD COLUMN IF NOT EXISTS key_material BYTEA NULL;
ALTER TABLE account_backup_keys ALTER COLUMN nonce DROP NOT NULL;
ALTER TABLE account_backup_keys ALTER COLUMN ciphertext DROP NOT NULL;
ALTER TABLE account_backup_keys DROP CONSTRAINT IF EXISTS account_backup_keys_at_rest_version_check;
ALTER TABLE account_backup_keys ADD CONSTRAINT account_backup_keys_at_rest_version_check CHECK (at_rest_version IN (1, 2));
ALTER TABLE account_backup_keys DROP CONSTRAINT IF EXISTS account_backup_keys_key_material_check;
ALTER TABLE account_backup_keys ADD CONSTRAINT account_backup_keys_key_material_check CHECK (key_material IS NULL OR octet_length(key_material) = 32);
ALTER TABLE account_backup_keys DROP CONSTRAINT IF EXISTS account_backup_keys_storage_shape_check;
ALTER TABLE account_backup_keys ADD CONSTRAINT account_backup_keys_storage_shape_check CHECK (
    (at_rest_version = 1 AND key_material IS NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL)
    OR
    (at_rest_version = 2 AND key_material IS NOT NULL AND nonce IS NULL AND ciphertext IS NULL)
);
