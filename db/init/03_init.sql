CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------
-- DROP OLD TABLES
-- ---------------------------------------------------

-- ---------------------------------------------------
-- SCANS
-- ---------------------------------------------------
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'running',
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    scan_metadata JSONB
);

CREATE INDEX idx_scans_cloud ON scans (cloud);
CREATE INDEX idx_scans_status ON scans (status);
CREATE INDEX idx_scans_started_at_desc ON scans (started_at DESC);

-- ---------------------------------------------------
-- RESOURCES
-- ---------------------------------------------------
CREATE TABLE resources (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cloud VARCHAR(50) NOT NULL,
    type VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    config JSONB,
    public BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_resources_scan_id ON resources (scan_id);
CREATE INDEX idx_resources_cloud ON resources (cloud);
CREATE INDEX idx_resources_public ON resources (public);

-- ---------------------------------------------------
-- FINDINGS
-- ---------------------------------------------------
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    severity VARCHAR(20),
    description TEXT,
    validated_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_findings_severity ON findings (severity);
CREATE INDEX idx_findings_resource_id ON findings (resource_id);

-- ---------------------------------------------------
-- VULNERABILITIES
-- ---------------------------------------------------
CREATE TABLE vulnerabilities (
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
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_vulns_severity ON vulnerabilities (severity);
CREATE INDEX idx_vulns_cvss ON vulnerabilities (cvss_score DESC);
CREATE INDEX idx_vulns_scan_id ON vulnerabilities (scan_id);
