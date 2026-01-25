-- Migration: Add aws_credential_id to scans table
-- This migration ensures scans can be linked to the credentials used

-- Add aws_credential_id column if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'scans' 
        AND column_name = 'aws_credential_id'
    ) THEN
        ALTER TABLE scans ADD COLUMN aws_credential_id INTEGER REFERENCES cloud_credentials(id) ON DELETE SET NULL;
        CREATE INDEX idx_scans_credential_id ON scans (aws_credential_id);
        RAISE NOTICE 'Added aws_credential_id column and index to scans table';
    ELSE
        RAISE NOTICE 'aws_credential_id column already exists in scans table';
    END IF;
END $$;
