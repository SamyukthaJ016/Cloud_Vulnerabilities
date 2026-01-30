-- Add missing columns to scan_schedules table

ALTER TABLE scan_schedules 
ADD COLUMN IF NOT EXISTS notify_email BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS email_address TEXT;

-- Add index for better query performance
CREATE INDEX IF NOT EXISTS idx_scan_schedules_notify ON scan_schedules (notify_email) WHERE notify_email = TRUE;
