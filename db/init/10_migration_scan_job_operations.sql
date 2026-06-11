-- Migration: operational controls for queued scan jobs

ALTER TABLE scan_jobs
ADD COLUMN IF NOT EXISTS last_error TEXT,
ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS worker_id VARCHAR(128);

ALTER TABLE scan_jobs
DROP CONSTRAINT IF EXISTS valid_scan_job_status;

ALTER TABLE scan_jobs
ADD CONSTRAINT valid_scan_job_status
CHECK (status IN ('queued','running','completed','failed','dead_letter','cancelled'));

CREATE INDEX IF NOT EXISTS idx_scan_jobs_dead_letter
ON scan_jobs (status, completed_at DESC)
WHERE status = 'dead_letter';
