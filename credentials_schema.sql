BEGIN;

-- ============================================================================
-- User Profiles
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_profiles (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    name VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_user_id
    ON user_profiles(user_id);

CREATE INDEX IF NOT EXISTS idx_user_profiles_email
    ON user_profiles(email);

-- ============================================================================
-- Cloud Credentials
-- ============================================================================
CREATE TABLE IF NOT EXISTS cloud_credentials (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL
        REFERENCES user_profiles(user_id) ON DELETE CASCADE,

    cloud_provider VARCHAR(50) NOT NULL,
    credential_name VARCHAR(255) NOT NULL,

    aws_access_key_id TEXT,
    aws_secret_access_key TEXT,
    aws_region VARCHAR(100) DEFAULT 'ap-south-1',
    aws_session_token TEXT,

    gcp_service_account_json TEXT,
    gcp_project_id VARCHAR(255),

    openai_api_key TEXT,
    openai_org_id VARCHAR(255),

    azure_client_id TEXT,
    azure_client_secret TEXT,
    azure_tenant_id TEXT,
    azure_subscription_id TEXT,

    is_default BOOLEAN DEFAULT FALSE,
    is_valid BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP,
    last_validated TIMESTAMP,
    validation_status VARCHAR(50) DEFAULT 'pending',
    validation_message TEXT,

    encrypted_secret_key TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    CONSTRAINT valid_cloud_provider
        CHECK (cloud_provider IN ('aws','gcp','openai','azure')),

    CONSTRAINT valid_validation_status
        CHECK (validation_status IN ('pending','valid','invalid')),

    CONSTRAINT uniq_user_provider_name
        UNIQUE (user_id, cloud_provider, credential_name)
);

CREATE INDEX IF NOT EXISTS idx_cloud_credentials_user_id
    ON cloud_credentials(user_id);

CREATE INDEX IF NOT EXISTS idx_cloud_credentials_provider
    ON cloud_credentials(cloud_provider);

CREATE INDEX IF NOT EXISTS idx_cloud_credentials_is_default
    ON cloud_credentials(is_default);

CREATE INDEX IF NOT EXISTS idx_cloud_credentials_is_valid
    ON cloud_credentials(is_valid);

-- ============================================================================
-- Scan Sessions
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(255) NOT NULL
        REFERENCES user_profiles(user_id) ON DELETE CASCADE,

    aws_credential_id INTEGER REFERENCES cloud_credentials(id),
    gcp_credential_id INTEGER REFERENCES cloud_credentials(id),
    openai_credential_id INTEGER REFERENCES cloud_credentials(id),
    azure_credential_id INTEGER REFERENCES cloud_credentials(id),

    status VARCHAR(50) DEFAULT 'active',
    scan_config JSONB,
    started_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    ended_at TIMESTAMP,

    ip_address INET,
    user_agent TEXT,
    session_token TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_session_id
    ON scan_sessions(session_id);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_user_id
    ON scan_sessions(user_id);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_status
    ON scan_sessions(status);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_expires_at
    ON scan_sessions(expires_at);

-- ============================================================================
-- Credential Audit Log
-- ============================================================================
CREATE TABLE IF NOT EXISTS credential_audit_log (
    id SERIAL PRIMARY KEY,
    credential_id INTEGER
        REFERENCES cloud_credentials(id) ON DELETE SET NULL,

    user_id VARCHAR(255),
    action VARCHAR(50) NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_credential_audit_log_credential_id
    ON credential_audit_log(credential_id);

CREATE INDEX IF NOT EXISTS idx_credential_audit_log_user_id
    ON credential_audit_log(user_id);

CREATE INDEX IF NOT EXISTS idx_credential_audit_log_action
    ON credential_audit_log(action);

CREATE INDEX IF NOT EXISTS idx_credential_audit_log_created_at
    ON credential_audit_log(created_at DESC);

-- ============================================================================
-- Trigger for updated_at
-- ============================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_cloud_credentials_updated_at ON cloud_credentials;

CREATE TRIGGER tr_cloud_credentials_updated_at
BEFORE UPDATE ON cloud_credentials
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Utility Functions
-- ============================================================================
CREATE OR REPLACE FUNCTION log_credential_usage(
    p_credential_id INTEGER,
    p_user_id VARCHAR,
    p_action VARCHAR,
    p_details JSONB DEFAULT NULL,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
)
RETURNS VOID AS $$
BEGIN
    INSERT INTO credential_audit_log (
        credential_id, user_id, action, details, ip_address, user_agent
    )
    VALUES (
        p_credential_id, p_user_id, p_action, p_details, p_ip_address, p_user_agent
    );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Views
-- ============================================================================
CREATE OR REPLACE VIEW v_user_credential_summary AS
SELECT
    u.user_id,
    u.email,
    u.name,
    COUNT(c.id) AS total_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'aws') AS aws_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'gcp') AS gcp_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'openai') AS openai_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'azure') AS azure_credentials,
    COUNT(*) FILTER (WHERE c.is_valid) AS valid_credentials,
    MAX(c.last_used) AS last_used_credential
FROM user_profiles u
LEFT JOIN cloud_credentials c ON u.user_id = c.user_id
GROUP BY u.user_id, u.email, u.name;

CREATE OR REPLACE VIEW v_active_sessions AS
SELECT
    s.session_id,
    s.user_id,
    s.status,
    s.started_at,
    s.expires_at,
    s.ip_address,
    u.email,
    u.name
FROM scan_sessions s
JOIN user_profiles u ON s.user_id = u.user_id
WHERE s.status = 'active';

-- ============================================================================
-- Default User
-- ============================================================================
INSERT INTO user_profiles (user_id, email, name)
VALUES ('anonymous', 'anonymous@cloudguard.local', 'Anonymous User')
ON CONFLICT (user_id) DO NOTHING;

COMMIT;

SELECT 'Credentials schema created successfully' AS status;
