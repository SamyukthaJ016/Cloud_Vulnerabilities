-- Tenant isolation for CloudGuard's core scanner and evidence records.
-- Existing single-user records retain their user ID as their legacy tenant;
-- every new application request receives its tenant from verified identity.

ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
UPDATE scan_jobs SET tenant_id = user_id WHERE tenant_id IS NULL OR tenant_id = '';
ALTER TABLE scan_jobs ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant_user_status
ON scan_jobs (tenant_id, user_id, status);

ALTER TABLE evidence_artifacts ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
UPDATE evidence_artifacts SET tenant_id = user_id WHERE tenant_id IS NULL OR tenant_id = '';
ALTER TABLE evidence_artifacts ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_tenant_user_control
ON evidence_artifacts (tenant_id, user_id, control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant_job
ON evidence_artifacts (tenant_id, job_id);
