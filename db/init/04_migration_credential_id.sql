-- Migration: Add credential_id to scan_schedules
-- This migration adds support for storing which credential to use for scheduled scans

-- Add credential_id column if it doesn't exist
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'scan_schedules' 
        AND column_name = 'credential_id'
    ) THEN
        ALTER TABLE scan_schedules ADD COLUMN credential_id INTEGER;
        RAISE NOTICE 'Added credential_id column to scan_schedules table';
    ELSE
        RAISE NOTICE 'credential_id column already exists in scan_schedules table';
    END IF;
END $$;
