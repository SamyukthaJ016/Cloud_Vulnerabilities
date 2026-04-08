BEGIN;

ALTER TABLE cloud_credentials
    ADD COLUMN IF NOT EXISTS kubernetes_kubeconfig TEXT,
    ADD COLUMN IF NOT EXISTS kubernetes_context VARCHAR(255),
    ADD COLUMN IF NOT EXISTS kubernetes_cluster_name VARCHAR(255);

ALTER TABLE scan_sessions
    ADD COLUMN IF NOT EXISTS kubernetes_credential_id INTEGER REFERENCES cloud_credentials(id);

ALTER TABLE cloud_credentials
    DROP CONSTRAINT IF EXISTS valid_cloud_provider;

ALTER TABLE cloud_credentials
    ADD CONSTRAINT valid_cloud_provider
    CHECK (cloud_provider IN ('aws','gcp','openai','azure','kubernetes'));

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
    COUNT(*) FILTER (WHERE c.is_valid) AS valid_credentials,
    MAX(c.last_used) AS last_used_credential
FROM user_profiles u
LEFT JOIN cloud_credentials c ON u.user_id = c.user_id
GROUP BY u.user_id, u.email, u.name;

COMMIT;
