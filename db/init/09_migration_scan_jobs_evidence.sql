-- Migration: queued scan jobs and evidence ingestion artifacts

CREATE TABLE IF NOT EXISTS scan_jobs (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(64) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    providers JSONB NOT NULL DEFAULT '[]'::jsonb,
    account_ids JSONB NOT NULL DEFAULT '{}'::jsonb,
    deep_scan BOOLEAN NOT NULL DEFAULT FALSE,
    offensive_scan BOOLEAN NOT NULL DEFAULT TRUE,
    credential_id INTEGER,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    priority INTEGER NOT NULL DEFAULT 100,
    scan_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    result JSONB,
    error TEXT,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_scan_job_status CHECK (status IN ('queued','running','completed','failed','cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_status ON scan_jobs (user_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_priority ON scan_jobs (status, priority, queued_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_job_id ON scan_jobs (job_id);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
    id SERIAL PRIMARY KEY,
    evidence_id VARCHAR(64) UNIQUE NOT NULL,
    job_id VARCHAR(64) REFERENCES scan_jobs(job_id) ON DELETE SET NULL,
    user_id VARCHAR(255) NOT NULL,
    control_id VARCHAR(255),
    control_name TEXT,
    source_system VARCHAR(255),
    scanner_type VARCHAR(100),
    artifact_type VARCHAR(100),
    storage_type VARCHAR(50) NOT NULL DEFAULT 'database',
    uri TEXT,
    filename TEXT,
    content_type VARCHAR(255),
    checksum_sha256 VARCHAR(64),
    payload JSONB,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_user_control ON evidence_artifacts (user_id, control_id);
CREATE INDEX IF NOT EXISTS idx_evidence_job ON evidence_artifacts (job_id);

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scan_jobs_updated_at ON scan_jobs;
CREATE TRIGGER scan_jobs_updated_at
BEFORE UPDATE ON scan_jobs
FOR EACH ROW EXECUTE FUNCTION update_updated_at();
