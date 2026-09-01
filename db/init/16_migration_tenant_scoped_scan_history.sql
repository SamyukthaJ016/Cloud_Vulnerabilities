-- Tenant isolation for legacy scan history. Child records inherit ownership
-- through scan_id, so the scans table is the sole tenant boundary for report
-- and dashboard queries.

ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id VARCHAR(255);
ALTER TABLE scans ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);

UPDATE scans
SET
    user_id = COALESCE(NULLIF(scan_metadata->>'user_id', ''), 'legacy-system'),
    tenant_id = COALESCE(
        NULLIF(scan_metadata->>'tenant_id', ''),
        NULLIF(scan_metadata->>'user_id', ''),
        'legacy-tenant'
    )
WHERE user_id IS NULL OR tenant_id IS NULL OR user_id = '' OR tenant_id = '';

ALTER TABLE scans ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE scans ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scans_tenant_user_started
ON scans (tenant_id, user_id, started_at DESC);
