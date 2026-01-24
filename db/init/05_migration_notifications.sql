-- Migration: Add email notification fields to scan_schedules
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS notify_email BOOLEAN DEFAULT FALSE;
ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS email_address TEXT;
