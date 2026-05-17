-- MSME compliance workspace for CERT-In 15 elemental controls.

CREATE TABLE IF NOT EXISTS msme_org_profiles (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    organization_name TEXT,
    udyam_registration_no TEXT,
    msme_type VARCHAR(20),
    industry TEXT,
    location TEXT,
    employee_count INTEGER,
    security_contact_name TEXT,
    security_contact_email TEXT,
    infrastructure_profile JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS msme_control_status (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    framework_code VARCHAR(50) NOT NULL DEFAULT 'CERTIN_MSME_2025_V1',
    control_code VARCHAR(20) NOT NULL,
    status VARCHAR(40) NOT NULL DEFAULT 'not_started',
    owner TEXT,
    due_date DATE,
    notes TEXT,
    score_override INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (user_id, framework_code, control_code)
);

CREATE TABLE IF NOT EXISTS msme_evidence (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    framework_code VARCHAR(50) NOT NULL DEFAULT 'CERTIN_MSME_2025_V1',
    control_code VARCHAR(20) NOT NULL,
    recommendation_code VARCHAR(20),
    title TEXT NOT NULL,
    evidence_type VARCHAR(40) NOT NULL DEFAULT 'document',
    file_name TEXT,
    file_url TEXT,
    notes TEXT,
    review_status VARCHAR(40) NOT NULL DEFAULT 'pending_review',
    evidence_date DATE,
    expires_at DATE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS msme_tasks (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    framework_code VARCHAR(50) NOT NULL DEFAULT 'CERTIN_MSME_2025_V1',
    control_code VARCHAR(20) NOT NULL,
    recommendation_code VARCHAR(20),
    title TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    owner TEXT,
    due_date DATE,
    status VARCHAR(40) NOT NULL DEFAULT 'open',
    source VARCHAR(40) NOT NULL DEFAULT 'manual',
    linked_scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS msme_audit_exports (
    id SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    framework_code VARCHAR(50) NOT NULL DEFAULT 'CERTIN_MSME_2025_V1',
    export_type VARCHAR(40) NOT NULL DEFAULT 'readiness_summary',
    export_payload JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_msme_control_status_user ON msme_control_status (user_id);
CREATE INDEX IF NOT EXISTS idx_msme_control_status_control ON msme_control_status (control_code);
CREATE INDEX IF NOT EXISTS idx_msme_evidence_user_control ON msme_evidence (user_id, control_code);
CREATE INDEX IF NOT EXISTS idx_msme_tasks_user_control ON msme_tasks (user_id, control_code);
CREATE INDEX IF NOT EXISTS idx_msme_tasks_status ON msme_tasks (status);

DROP TRIGGER IF EXISTS msme_org_profiles_updated_at ON msme_org_profiles;
CREATE TRIGGER msme_org_profiles_updated_at
BEFORE UPDATE ON msme_org_profiles
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS msme_control_status_updated_at ON msme_control_status;
CREATE TRIGGER msme_control_status_updated_at
BEFORE UPDATE ON msme_control_status
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS msme_evidence_updated_at ON msme_evidence;
CREATE TRIGGER msme_evidence_updated_at
BEFORE UPDATE ON msme_evidence
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS msme_tasks_updated_at ON msme_tasks;
CREATE TRIGGER msme_tasks_updated_at
BEFORE UPDATE ON msme_tasks
FOR EACH ROW EXECUTE FUNCTION update_updated_at();
