-- Migration: sandbox lab orchestration
--
-- Tracks short-lived vulnerable lab resources used for live demos and scanner
-- validation. The platform creates resources inside existing sandbox
-- accounts/projects/namespaces, scans them, stores proof, and then destroys
-- them after scan completion or TTL expiry.

CREATE TABLE IF NOT EXISTS sandbox_lab_runs (
    id SERIAL PRIMARY KEY,
    lab_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    lab_type VARCHAR(128) NOT NULL DEFAULT 'default',
    status VARCHAR(32) NOT NULL DEFAULT 'requested',
    ttl_minutes INTEGER NOT NULL DEFAULT 5,
    credential_id INTEGER REFERENCES cloud_credentials(id) ON DELETE SET NULL,
    region VARCHAR(128),
    namespace VARCHAR(128),
    resource_prefix VARCHAR(128) NOT NULL,
    deploy_mode VARCHAR(64) NOT NULL DEFAULT 'pending',
    auto_destroy BOOLEAN NOT NULL DEFAULT TRUE,
    scan_after_deploy BOOLEAN NOT NULL DEFAULT TRUE,
    scan_job_id VARCHAR(64) REFERENCES scan_jobs(job_id) ON DELETE SET NULL,
    validation_id VARCHAR(64) REFERENCES security_validation_jobs(validation_id) ON DELETE SET NULL,
    evidence_id VARCHAR(64) REFERENCES evidence_artifacts(evidence_id) ON DELETE SET NULL,
    remediation_action_id VARCHAR(64) REFERENCES remediation_actions(action_id) ON DELETE SET NULL,
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    proof_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    cleanup_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    error TEXT,
    worker_id VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    deployed_at TIMESTAMPTZ,
    scan_started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_sandbox_lab_provider
        CHECK (provider IN ('aws','gcp','kubernetes','iac')),
    CONSTRAINT valid_sandbox_lab_status
        CHECK (status IN ('requested','provisioning','deployed','scanning','scan_completed','destroying','destroyed','completed','failed','expired','cancelled')),
    CONSTRAINT valid_sandbox_lab_ttl
        CHECK (ttl_minutes BETWEEN 1 AND 240)
);

CREATE INDEX IF NOT EXISTS idx_sandbox_lab_runs_user_status
ON sandbox_lab_runs (user_id, tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_sandbox_lab_runs_expires
ON sandbox_lab_runs (status, expires_at);

CREATE INDEX IF NOT EXISTS idx_sandbox_lab_runs_provider
ON sandbox_lab_runs (tenant_id, provider, created_at DESC);


CREATE TABLE IF NOT EXISTS sandbox_lab_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    lab_id VARCHAR(64) NOT NULL REFERENCES sandbox_lab_runs(lab_id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    message TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sandbox_lab_events_lab_created
ON sandbox_lab_events (lab_id, created_at DESC);


DROP TRIGGER IF EXISTS sandbox_lab_runs_updated_at ON sandbox_lab_runs;
CREATE TRIGGER sandbox_lab_runs_updated_at
BEFORE UPDATE ON sandbox_lab_runs
FOR EACH ROW EXECUTE FUNCTION update_updated_at();
