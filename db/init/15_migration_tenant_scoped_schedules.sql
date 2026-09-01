-- Tenant isolation for scheduled scans. Existing records remain accessible to
-- their original owner through the legacy user-as-tenant mapping.

ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
UPDATE scan_schedules SET tenant_id = user_id WHERE tenant_id IS NULL OR tenant_id = '';
ALTER TABLE scan_schedules ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_schedules_tenant_user_status
ON scan_schedules (tenant_id, user_id, status);
