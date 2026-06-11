-- Migration: add schedule update tracking and scheduler query indexes
ALTER TABLE scan_schedules
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_scan_schedules_due
  ON scan_schedules (status, next_run_at);

CREATE INDEX IF NOT EXISTS idx_scan_schedules_user_status
  ON scan_schedules (user_id, status);

DROP TRIGGER IF EXISTS scan_schedules_updated_at ON scan_schedules;
CREATE TRIGGER scan_schedules_updated_at
BEFORE UPDATE ON scan_schedules
FOR EACH ROW EXECUTE FUNCTION update_updated_at();
