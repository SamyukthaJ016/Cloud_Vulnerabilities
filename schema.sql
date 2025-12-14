-- ============================================================================
-- Multi-Cloud Security Scanner - Complete Database Schema
-- ============================================================================

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Drop existing tables (for clean setup)
-- ============================================================================
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS resources CASCADE;
DROP TABLE IF EXISTS scans CASCADE;

-- ============================================================================
-- Scans Table - Master table for all security scans
-- ============================================================================
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,  -- 'aws', 'gcp', 'openai'
    status VARCHAR(50) DEFAULT 'running',  -- 'running', 'completed', 'failed'
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    scan_metadata JSONB,  -- Store additional scan configuration
    
    -- Indexes for performance
    INDEX idx_scans_cloud (cloud),
    INDEX idx_scans_status (status),
    INDEX idx_scans_started_at (started_at DESC)
);

-- ============================================================================
-- Resources Table - All cloud resources discovered
-- ============================================================================
CREATE TABLE resources (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cloud VARCHAR(50) NOT NULL,  -- 'aws', 'gcp', 'openai'
    type VARCHAR(100) NOT NULL,  -- 's3_bucket', 'iam_user', 'gcs_bucket', etc.
    name VARCHAR(500) NOT NULL,
    region VARCHAR(100) DEFAULT 'global',
    config JSONB,  -- Full resource configuration as JSON
    public BOOLEAN DEFAULT FALSE,
    tags JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes for performance
    INDEX idx_resources_scan_id (scan_id),
    INDEX idx_resources_cloud (cloud),
    INDEX idx_resources_type (type),
    INDEX idx_resources_public (public),
    INDEX idx_resources_name (name)
);

-- ============================================================================
-- Findings Table - Security findings from config scans
-- ============================================================================
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,  -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    description TEXT NOT NULL,
    recommendation TEXT,
    validated_by VARCHAR(100),  -- Tool/plugin that found this (e.g., 'aws', 'gcp')
    compliance_frameworks TEXT[],  -- Array of compliance frameworks (e.g., ['CIS-1.2', 'NIST-800-53'])
    false_positive BOOLEAN DEFAULT FALSE,
    remediated BOOLEAN DEFAULT FALSE,
    remediated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes for performance
    INDEX idx_findings_scan_id (scan_id),
    INDEX idx_findings_resource_id (resource_id),
    INDEX idx_findings_severity (severity),
    INDEX idx_findings_remediated (remediated),
    
    -- Constraint to ensure valid severity levels
    CONSTRAINT valid_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
);

-- ============================================================================
-- Vulnerabilities Table - CVE/vulnerability scanning results
-- ============================================================================
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    vuln_id VARCHAR(100) NOT NULL,  -- CVE-2023-1234 or tool-specific ID
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    description TEXT,
    affected_package VARCHAR(255),
    fixed_version VARCHAR(100),
    cvss_score DECIMAL(3,1),  -- 0.0 to 10.0
    tool VARCHAR(50) NOT NULL,  -- 'trivy', 'safety', 'gitleaks', etc.
    reference_urls JSONB,  -- Array of reference URLs as JSON
    exploitable BOOLEAN DEFAULT FALSE,
    patched BOOLEAN DEFAULT FALSE,
    patched_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- Indexes for performance
    INDEX idx_vulnerabilities_scan_id (scan_id),
    INDEX idx_vulnerabilities_resource_id (resource_id),
    INDEX idx_vulnerabilities_vuln_id (vuln_id),
    INDEX idx_vulnerabilities_severity (severity),
    INDEX idx_vulnerabilities_tool (tool),
    INDEX idx_vulnerabilities_cvss_score (cvss_score DESC),
    INDEX idx_vulnerabilities_patched (patched),
    
    -- Constraint to ensure valid severity levels
    CONSTRAINT valid_vuln_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
);

-- ============================================================================
-- Summary Views for Dashboard
-- ============================================================================

-- Multi-cloud summary view
CREATE OR REPLACE VIEW v_multi_cloud_summary AS
SELECT 
    r.cloud,
    COUNT(DISTINCT r.id) as resource_count,
    COUNT(DISTINCT f.id) as finding_count,
    COUNT(DISTINCT CASE WHEN r.public = true THEN r.id END) as public_resource_count,
    COUNT(DISTINCT v.id) as vulnerability_count,
    COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.id END) as critical_vuln_count
FROM resources r
LEFT JOIN findings f ON r.id = f.resource_id
LEFT JOIN vulnerabilities v ON r.id = v.resource_id
GROUP BY r.cloud;

-- Recent scans view
CREATE OR REPLACE VIEW v_recent_scans AS
SELECT 
    s.id,
    s.account_id,
    s.cloud,
    s.status,
    s.started_at,
    s.completed_at,
    COUNT(DISTINCT r.id) as resource_count,
    COUNT(DISTINCT f.id) as finding_count,
    COUNT(DISTINCT v.id) as vulnerability_count
FROM scans s
LEFT JOIN resources r ON s.id = r.scan_id
LEFT JOIN findings f ON s.id = f.scan_id
LEFT JOIN vulnerabilities v ON s.id = v.scan_id
GROUP BY s.id, s.account_id, s.cloud, s.status, s.started_at, s.completed_at
ORDER BY s.started_at DESC
LIMIT 10;

-- Top vulnerabilities view
CREATE OR REPLACE VIEW v_top_vulnerabilities AS
SELECT 
    v.vuln_id,
    v.title,
    v.severity,
    v.cvss_score,
    v.affected_package,
    v.tool,
    r.name as resource_name,
    r.cloud,
    COUNT(*) as occurrence_count
FROM vulnerabilities v
JOIN resources r ON v.resource_id = r.id
WHERE v.patched = false
GROUP BY v.vuln_id, v.title, v.severity, v.cvss_score, v.affected_package, v.tool, r.name, r.cloud
ORDER BY v.cvss_score DESC NULLS LAST, occurrence_count DESC
LIMIT 20;

-- ============================================================================
-- Audit Triggers
-- ============================================================================

-- Function to update scan completion
CREATE OR REPLACE FUNCTION update_scan_completion()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.status = 'completed' AND OLD.status != 'completed' THEN
        NEW.completed_at := NOW();
        NEW.duration_seconds := EXTRACT(EPOCH FROM (NOW() - NEW.started_at))::INTEGER;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for scan completion
DROP TRIGGER IF EXISTS tr_update_scan_completion ON scans;
CREATE TRIGGER tr_update_scan_completion
    BEFORE UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_scan_completion();

-- ============================================================================
-- Sample Data for Testing (Optional - remove in production)
-- ============================================================================

-- Uncomment below for test data
/*
INSERT INTO scans (account_id, cloud, status) VALUES 
    ('123456789012', 'aws', 'completed'),
    ('my-gcp-project', 'gcp', 'completed'),
    ('default', 'openai', 'completed');

INSERT INTO resources (scan_id, cloud, type, name, public) VALUES
    (1, 'aws', 's3_bucket', 'test-bucket-public', true),
    (1, 'aws', 'iam_user', 'test-user', false),
    (2, 'gcp', 'gcs_bucket', 'test-gcp-bucket', false);

INSERT INTO findings (scan_id, resource_id, severity, description, validated_by) VALUES
    (1, 1, 'CRITICAL', 'S3 bucket is publicly accessible', 'aws'),
    (1, 2, 'HIGH', 'IAM user without MFA', 'aws');
*/

-- ============================================================================
-- Grant Permissions
-- ============================================================================

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scanner_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scanner_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO scanner_user;

-- ============================================================================
-- Verification Queries
-- ============================================================================

-- Show all tables
SELECT tablename FROM pg_tables WHERE schemaname = 'public';

-- Show table sizes
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

ANALYZE;

