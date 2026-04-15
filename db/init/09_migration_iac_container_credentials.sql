BEGIN;

ALTER TABLE cloud_credentials
    ADD COLUMN IF NOT EXISTS iac_target_path TEXT,
    ADD COLUMN IF NOT EXISTS iac_enabled_tools TEXT,
    ADD COLUMN IF NOT EXISTS container_image_target TEXT,
    ADD COLUMN IF NOT EXISTS container_path_target TEXT,
    ADD COLUMN IF NOT EXISTS container_enabled_tools TEXT,
    ADD COLUMN IF NOT EXISTS container_sbom_tools TEXT;

ALTER TABLE cloud_credentials
    DROP CONSTRAINT IF EXISTS valid_cloud_provider;

ALTER TABLE cloud_credentials
    ADD CONSTRAINT valid_cloud_provider
    CHECK (cloud_provider IN ('aws','gcp','openai','azure','kubernetes','iac','container'));

DROP VIEW IF EXISTS v_user_credential_summary;

CREATE VIEW v_user_credential_summary AS
SELECT
    u.user_id,
    u.email,
    u.name,
    COUNT(c.id) AS total_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'aws') AS aws_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'gcp') AS gcp_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'openai') AS openai_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'azure') AS azure_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'kubernetes') AS kubernetes_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'iac') AS iac_credentials,
    COUNT(*) FILTER (WHERE c.cloud_provider = 'container') AS container_credentials,
    COUNT(*) FILTER (WHERE c.is_valid) AS valid_credentials,
    MAX(c.last_used) AS last_used_credential
FROM user_profiles u
LEFT JOIN cloud_credentials c ON u.user_id = c.user_id
GROUP BY u.user_id, u.email, u.name;

COMMIT;
