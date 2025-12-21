-- =============================================================================
-- Multi-Cloud Security Scanner Database Schema
-- PostgreSQL 15+
-- =============================================================================

-- Drop existing tables (for fresh setup)
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS resources CASCADE;
DROP TABLE IF EXISTS scans CASCADE;

-- =============================================================================
-- SCANS TABLE
-- =============================================================================
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,  -- aws, gcp, openai, azure
    status VARCHAR(50) DEFAULT 'running',  -- running, completed, failed
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds DECIMAL(10, 2),
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for scans
CREATE INDEX idx_scans_cloud ON scans(cloud);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_started_at ON scans(started_at DESC);
CREATE INDEX idx_scans_account_id ON scans(account_id);

-- =============================================================================
-- RESOURCES TABLE
-- =============================================================================
CREATE TABLE resources (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cloud VARCHAR(50) NOT NULL,  -- aws, gcp, openai, azure
    type VARCHAR(100) NOT NULL,  -- s3_bucket, iam_user, gcs_bucket, etc.
    name VARCHAR(500) NOT NULL,
    region VARCHAR(100) DEFAULT 'global',
    config JSONB DEFAULT '{}'::jsonb,  -- Full resource configuration
    public BOOLEAN DEFAULT FALSE,  -- Is resource publicly accessible?
    tags JSONB DEFAULT '{}'::jsonb,  -- Resource tags
    risk_score INTEGER DEFAULT 0,  -- Calculated risk score (0-100)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for resources
CREATE INDEX idx_resources_scan_id ON resources(scan_id);
CREATE INDEX idx_resources_cloud ON resources(cloud);
CREATE INDEX idx_resources_type ON resources(type);
CREATE INDEX idx_resources_name ON resources(name);
CREATE INDEX idx_resources_public ON resources(public);
CREATE INDEX idx_resources_risk_score ON resources(risk_score DESC);
CREATE INDEX idx_resources_config_gin ON resources USING GIN (config);

-- =============================================================================
-- FINDINGS TABLE
-- =============================================================================
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER REFERENCES resources(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    description TEXT NOT NULL,
    recommendation TEXT,
    cve_id VARCHAR(50),  -- CVE identifier if applicable
    compliance TEXT[],  -- Array of compliance frameworks (CIS, NIST, etc.)
    validated_by VARCHAR(100),  -- Source/tool that detected this (aws, trivy, etc.)
    tool_category VARCHAR(50),  -- config_scan, vuln_scan, secret_scan, web_scan
    detection_tool VARCHAR(100),  -- Specific tool name (TRIVY, GITLEAKS, etc.)
    remediation_priority INTEGER DEFAULT 5,  -- 1-10 priority
    false_positive BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    resolved_by VARCHAR(255),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_resource_id ON findings(resource_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_cve_id ON findings(cve_id);
CREATE INDEX idx_findings_resolved ON findings(resolved);
CREATE INDEX idx_findings_detection_tool ON findings(detection_tool);
CREATE INDEX idx_findings_tool_category ON findings(tool_category);
CREATE INDEX idx_findings_created_at ON findings(created_at DESC);

-- =============================================================================
-- VULNERABILITIES TABLE (NEW - Enhanced vulnerability tracking)
-- =============================================================================
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER REFERENCES resources(id) ON DELETE CASCADE,
    vuln_id VARCHAR(100) NOT NULL,  -- CVE-2023-1234 or tool-specific ID
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    description TEXT,
    affected_package VARCHAR(255),  -- Package name
    installed_version VARCHAR(100),  -- Currently installed version
    fixed_version VARCHAR(100),  -- Version that fixes the vulnerability
    cvss_score DECIMAL(3, 1),  -- CVSS score (0.0 - 10.0)
    cvss_vector VARCHAR(100),  -- CVSS vector string
    tool VARCHAR(50) NOT NULL,  -- trivy, safety, gitleaks, etc.
    reference_urls JSONB DEFAULT '[]'::jsonb,  -- Array of reference URLs
    exploit_available BOOLEAN DEFAULT FALSE,
    patch_available BOOLEAN DEFAULT TRUE,
    remediation_effort VARCHAR(20),  -- low, medium, high
    false_positive BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,
    first_detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for vulnerabilities
CREATE INDEX idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_resource_id ON vulnerabilities(resource_id);
CREATE INDEX idx_vulns_vuln_id ON vulnerabilities(vuln_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cvss_score ON vulnerabilities(cvss_score DESC);
CREATE INDEX idx_vulns_tool ON vulnerabilities(tool);
CREATE INDEX idx_vulns_resolved ON vulnerabilities(resolved);
CREATE INDEX idx_vulns_affected_package ON vulnerabilities(affected_package);

-- =============================================================================
-- UTILITY VIEWS
-- =============================================================================

-- View: Latest scan per cloud provider
CREATE OR REPLACE VIEW latest_scans AS
SELECT DISTINCT ON (cloud) 
    id, account_id, cloud, status, started_at, completed_at
FROM scans
ORDER BY cloud, started_at DESC;

-- View: Critical findings summary
CREATE OR REPLACE VIEW critical_findings AS
SELECT 
    s.id as scan_id,
    s.cloud,
    s.started_at,
    COUNT(f.id) as critical_count,
    array_agg(DISTINCT r.type) as affected_resource_types
FROM scans s
JOIN findings f ON s.id = f.scan_id
JOIN resources r ON f.resource_id = r.id
WHERE f.severity = 'CRITICAL' AND f.resolved = FALSE
GROUP BY s.id, s.cloud, s.started_at
ORDER BY s.started_at DESC;

-- View: Vulnerability statistics
CREATE OR REPLACE VIEW vulnerability_stats AS
SELECT 
    v.tool,
    v.severity,
    COUNT(*) as count,
    COUNT(DISTINCT v.vuln_id) as unique_vulns,
    AVG(v.cvss_score) as avg_cvss
FROM vulnerabilities v
WHERE v.resolved = FALSE
GROUP BY v.tool, v.severity
ORDER BY v.tool, 
    CASE v.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END;

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function: Update timestamp on row update
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update trigger to all tables
CREATE TRIGGER scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER resources_updated_at BEFORE UPDATE ON resources
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER vulnerabilities_updated_at BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function: Calculate resource risk score
CREATE OR REPLACE FUNCTION calculate_risk_score(resource_id_param INTEGER)
RETURNS INTEGER AS $$
DECLARE
    risk_score INTEGER := 0;
    critical_count INTEGER;
    high_count INTEGER;
    is_public BOOLEAN;
BEGIN
    -- Get finding counts
    SELECT 
        COUNT(*) FILTER (WHERE severity = 'CRITICAL'),
        COUNT(*) FILTER (WHERE severity = 'HIGH')
    INTO critical_count, high_count
    FROM findings
    WHERE findings.resource_id = resource_id_param AND resolved = FALSE;
    
    -- Get public status
    SELECT public INTO is_public
    FROM resources
    WHERE id = resource_id_param;
    
    -- Calculate score
    risk_score := (critical_count * 25) + (high_count * 10);
    
    IF is_public THEN
        risk_score := risk_score + 20;
    END IF;
    
    -- Cap at 100
    IF risk_score > 100 THEN
        risk_score := 100;
    END IF;
    
    RETURN risk_score;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- GRANT PERMISSIONS
-- =============================================================================

-- Grant all privileges to scanner_user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO scanner_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO scanner_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO scanner_user;

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE scans IS 'Security scan execution records';
COMMENT ON TABLE resources IS 'Discovered cloud resources';
COMMENT ON TABLE findings IS 'Security findings and misconfigurations';
COMMENT ON TABLE vulnerabilities IS 'Detailed vulnerability tracking from scanning tools';

COMMENT ON COLUMN vulnerabilities.tool IS 'Scanner tool: trivy, safety, gitleaks, zap, nuclei, etc.';
COMMENT ON COLUMN findings.detection_tool IS 'Tool that detected the finding (extracted from description)';
COMMENT ON COLUMN findings.tool_category IS 'Category: config_scan, vuln_scan, secret_scan, web_scan';

-- =============================================================================
-- SUCCESS MESSAGE
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE '✅ Database schema initialized successfully!';
    RAISE NOTICE '📊 Tables created: scans, resources, findings, vulnerabilities';
    RAISE NOTICE '🔍 Views created: latest_scans, critical_findings, vulnerability_stats';
    RAISE NOTICE '⚙️  Functions created: update_updated_at, calculate_risk_score';
END $$;