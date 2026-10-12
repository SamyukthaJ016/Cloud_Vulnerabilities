-- Migration: add user_id to scans for per-user data isolation

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'scans'
          AND column_name = 'user_id'
    ) THEN
        ALTER TABLE scans ADD COLUMN user_id TEXT;
        RAISE NOTICE 'Added user_id column to scans table';
    ELSE
        RAISE NOTICE 'user_id column already exists in scans table';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans (user_id);

UPDATE scans s
SET user_id = c.user_id
FROM cloud_credentials c
WHERE s.user_id IS NULL
  AND s.aws_credential_id = c.id;
