


-- CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -- ===================================================
-- -- SCANS
-- -- ===================================================
-- CREATE TABLE IF NOT EXISTS scans (
--     id SERIAL PRIMARY KEY,
--     account_id VARCHAR(255) NOT NULL,
--     cloud VARCHAR(50) NOT NULL,
--     status VARCHAR(50) DEFAULT 'running',
--     started_at TIMESTAMP DEFAULT NOW(),
--     completed_at TIMESTAMP,
--     duration_seconds INTEGER,
--     error_message TEXT,
--     scan_metadata JSONB,
--     created_at TIMESTAMP DEFAULT NOW(),
--     updated_at TIMESTAMP DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_scans_cloud ON scans (cloud);
-- CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
-- CREATE INDEX IF NOT EXISTS idx_scans_started_at_desc ON scans (started_at DESC);

-- -- ===================================================
-- -- RESOURCES
-- -- ===================================================
-- CREATE TABLE IF NOT EXISTS resources (
--     id SERIAL PRIMARY KEY,
--     scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
--     cloud VARCHAR(50) NOT NULL,
--     type VARCHAR(100) NOT NULL,
--     name VARCHAR(255) NOT NULL,
--     config JSONB,
--     public BOOLEAN DEFAULT FALSE,
--     created_at TIMESTAMP DEFAULT NOW(),
--     updated_at TIMESTAMP DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_resources_scan_id ON resources (scan_id);
-- CREATE INDEX IF NOT EXISTS idx_resources_cloud ON resources (cloud);
-- CREATE INDEX IF NOT EXISTS idx_resources_public ON resources (public);

-- -- ===================================================
-- -- FINDINGS
-- -- ===================================================
-- CREATE TABLE IF NOT EXISTS findings (
--     id SERIAL PRIMARY KEY,
--     scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
--     resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
--     severity VARCHAR(20),
--     description TEXT,
--     validated_by VARCHAR(50),
--     created_at TIMESTAMP DEFAULT NOW(),
--     updated_at TIMESTAMP DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
-- CREATE INDEX IF NOT EXISTS idx_findings_resource_id ON findings (resource_id);

-- -- ===================================================
-- -- VULNERABILITIES
-- -- ===================================================
-- CREATE TABLE IF NOT EXISTS vulnerabilities (
--     id SERIAL PRIMARY KEY,
--     scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
--     resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
--     vuln_id VARCHAR(100),
--     title VARCHAR(500),
--     severity VARCHAR(20),
--     description TEXT,
--     affected_package VARCHAR(255),
--     fixed_version VARCHAR(100),
--     cvss_score NUMERIC(4,2),
--     tool VARCHAR(50),
--     reference_urls JSONB,
--     created_at TIMESTAMP DEFAULT NOW(),
--     updated_at TIMESTAMP DEFAULT NOW()
-- );

-- CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);
-- CREATE INDEX IF NOT EXISTS idx_vulns_cvss ON vulnerabilities (cvss_score DESC);
-- CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities (scan_id);

-- -- ===================================================
-- -- UPDATED_AT TRIGGER
-- -- ===================================================
-- CREATE OR REPLACE FUNCTION update_updated_at()
-- RETURNS TRIGGER AS $$
-- BEGIN
--     NEW.updated_at = NOW();
--     RETURN NEW;
-- END;
-- $$ LANGUAGE plpgsql;

-- DROP TRIGGER IF EXISTS scans_updated_at ON scans;
-- CREATE TRIGGER scans_updated_at
-- BEFORE UPDATE ON scans
-- FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- DROP TRIGGER IF EXISTS resources_updated_at ON resources;
-- CREATE TRIGGER resources_updated_at
-- BEFORE UPDATE ON resources
-- FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- DROP TRIGGER IF EXISTS findings_updated_at ON findings;
-- CREATE TRIGGER findings_updated_at
-- BEFORE UPDATE ON findings
-- FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- DROP TRIGGER IF EXISTS vulnerabilities_updated_at ON vulnerabilities;
-- CREATE TRIGGER vulnerabilities_updated_at
-- BEFORE UPDATE ON vulnerabilities
-- FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- DO $$
-- BEGIN
--     RAISE NOTICE '✅ Database schema initialized successfully!';
-- END $$;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


-- ===================================================
-- SCANS
-- ===================================================
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'running',
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    scan_metadata JSONB,
    aws_credential_id INTEGER REFERENCES cloud_credentials(id) ON DELETE SET NULL, -- Improved: Link to credentials
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_cloud ON scans (cloud);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_started_at_desc ON scans (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_credential_id ON scans (aws_credential_id);


-- ===================================================
-- RESOURCES
-- ===================================================
CREATE TABLE IF NOT EXISTS resources (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cloud VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    config JSONB,
    public BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_resources_scan_id ON resources (scan_id);
CREATE INDEX IF NOT EXISTS idx_resources_cloud ON resources (cloud);
CREATE INDEX IF NOT EXISTS idx_resources_public ON resources (public);


-- ===================================================
-- FINDINGS
-- ===================================================
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    severity VARCHAR(20),
    description TEXT,
    validated_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_resource_id ON findings (resource_id);


-- ===================================================
-- VULNERABILITIES
-- ===================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    vuln_id VARCHAR(100),
    title VARCHAR(500),
    severity VARCHAR(20),
    description TEXT,
    affected_package VARCHAR(255),
    fixed_version VARCHAR(100),
    cvss_score NUMERIC(4,2),
    tool VARCHAR(50),
    reference_urls JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulns_cvss ON vulnerabilities (cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities (scan_id);


-- ===================================================
-- SCHEDULED SCANS
-- ===================================================
CREATE TABLE IF NOT EXISTS scan_schedules (
  id SERIAL PRIMARY KEY,
  user_id TEXT NOT NULL,
  providers TEXT NOT NULL,
  account_ids TEXT NOT NULL,
  deep_scan BOOLEAN NOT NULL DEFAULT FALSE,
  schedule JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'scheduled',
  next_run_at TIMESTAMPTZ NOT NULL,
  credential_id INTEGER,  -- NEW: Store which credential to use
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_schedules_due ON scan_schedules (status, next_run_at);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_user_status ON scan_schedules (user_id, status);


-- ===================================================
-- SCAN JOB QUEUE
-- ===================================================
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
    last_error TEXT,
    locked_at TIMESTAMPTZ,
    worker_id VARCHAR(128),
    queued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_scan_job_status CHECK (status IN ('queued','running','completed','failed','dead_letter','cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_user_status ON scan_jobs (user_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status_priority ON scan_jobs (status, priority, queued_at);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_job_id ON scan_jobs (job_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_dead_letter ON scan_jobs (status, completed_at DESC) WHERE status = 'dead_letter';


-- ===================================================
-- EVIDENCE ARTIFACTS
-- ===================================================
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


-- ===================================================
-- UPDATED_AT TRIGGER
-- ===================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scans_updated_at ON scans;
CREATE TRIGGER scans_updated_at
BEFORE UPDATE ON scans
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS resources_updated_at ON resources;
CREATE TRIGGER resources_updated_at
BEFORE UPDATE ON resources
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS findings_updated_at ON findings;
CREATE TRIGGER findings_updated_at
BEFORE UPDATE ON findings
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS vulnerabilities_updated_at ON vulnerabilities;
CREATE TRIGGER vulnerabilities_updated_at
BEFORE UPDATE ON vulnerabilities
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS scan_schedules_updated_at ON scan_schedules;
CREATE TRIGGER scan_schedules_updated_at
BEFORE UPDATE ON scan_schedules
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS scan_jobs_updated_at ON scan_jobs;
CREATE TRIGGER scan_jobs_updated_at
BEFORE UPDATE ON scan_jobs
FOR EACH ROW EXECUTE FUNCTION update_updated_at();


DO $$
BEGIN
    RAISE NOTICE '✅ Database schema initialized successfully!';
END $$;
