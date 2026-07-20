-- Migration: vendor-neutral reason-and-act workflow
--
-- This adds the platform layer needed for contextual prioritization,
-- sandbox validation proof, remediation approvals, and STRIDE threat models.

CREATE TABLE IF NOT EXISTS asset_risk_contexts (
    id SERIAL PRIMARY KEY,
    context_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    asset_ref TEXT NOT NULL,
    provider VARCHAR(64),
    asset_type VARCHAR(128),
    asset_name TEXT,
    business_criticality VARCHAR(32) NOT NULL DEFAULT 'medium',
    internet_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    data_classification VARCHAR(64) NOT NULL DEFAULT 'internal',
    environment VARCHAR(64) NOT NULL DEFAULT 'unknown',
    owner VARCHAR(255),
    tags JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    identity_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    custom_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_asset_business_criticality
        CHECK (business_criticality IN ('low','medium','high','critical')),
    CONSTRAINT valid_asset_data_classification
        CHECK (data_classification IN ('public','internal','confidential','restricted','regulated'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_risk_contexts_tenant_asset
ON asset_risk_contexts (tenant_id, asset_ref);

CREATE INDEX IF NOT EXISTS idx_asset_risk_contexts_user
ON asset_risk_contexts (user_id, tenant_id);


CREATE TABLE IF NOT EXISTS security_validation_jobs (
    id SERIAL PRIMARY KEY,
    validation_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    finding_ref TEXT NOT NULL,
    job_id VARCHAR(64) REFERENCES scan_jobs(job_id) ON DELETE SET NULL,
    evidence_id VARCHAR(64) REFERENCES evidence_artifacts(evidence_id) ON DELETE SET NULL,
    asset_ref TEXT,
    validation_type VARCHAR(64) NOT NULL DEFAULT 'sandbox',
    status VARCHAR(32) NOT NULL DEFAULT 'requested',
    safety_guardrails JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    proof_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    proof_uri TEXT,
    result_summary TEXT,
    requested_by VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_validation_type
        CHECK (validation_type IN ('sandbox','configuration_recheck','safe_probe','iac_plan','manual')),
    CONSTRAINT valid_validation_status
        CHECK (status IN ('requested','queued','running','validated','not_reproducible','unsafe','failed','expired','cancelled'))
);

CREATE INDEX IF NOT EXISTS idx_security_validation_jobs_user_status
ON security_validation_jobs (user_id, tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_security_validation_jobs_finding_ref
ON security_validation_jobs (tenant_id, finding_ref);


CREATE TABLE IF NOT EXISTS remediation_actions (
    id SERIAL PRIMARY KEY,
    action_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    finding_ref TEXT NOT NULL,
    validation_id VARCHAR(64) REFERENCES security_validation_jobs(validation_id) ON DELETE SET NULL,
    mode VARCHAR(32) NOT NULL DEFAULT 'learn',
    status VARCHAR(32) NOT NULL DEFAULT 'proposed',
    title TEXT NOT NULL,
    priority VARCHAR(32) NOT NULL DEFAULT 'medium',
    risk_score INTEGER NOT NULL DEFAULT 0,
    action_type VARCHAR(64) NOT NULL DEFAULT 'manual',
    recommended_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
    automation_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence_id VARCHAR(64) REFERENCES evidence_artifacts(evidence_id) ON DELETE SET NULL,
    requested_by VARCHAR(255),
    approved_by VARCHAR(255),
    approval_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_remediation_mode
        CHECK (mode IN ('learn','approve','enforce')),
    CONSTRAINT valid_remediation_status
        CHECK (status IN ('proposed','pending_approval','approved','rejected','executing','completed','failed','rolled_back')),
    CONSTRAINT valid_remediation_priority
        CHECK (priority IN ('low','medium','high','critical'))
);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_user_status
ON remediation_actions (user_id, tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_finding_ref
ON remediation_actions (tenant_id, finding_ref);


CREATE TABLE IF NOT EXISTS threat_models (
    id SERIAL PRIMARY KEY,
    threat_model_id VARCHAR(64) UNIQUE NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    user_id VARCHAR(255) NOT NULL,
    scope TEXT NOT NULL,
    source_type VARCHAR(64) NOT NULL DEFAULT 'manual',
    input_artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    stride_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'generated',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_threat_model_status
        CHECK (status IN ('draft','generated','reviewed','archived'))
);

CREATE INDEX IF NOT EXISTS idx_threat_models_user_status
ON threat_models (user_id, tenant_id, status);


DROP TRIGGER IF EXISTS asset_risk_contexts_updated_at ON asset_risk_contexts;
CREATE TRIGGER asset_risk_contexts_updated_at
BEFORE UPDATE ON asset_risk_contexts
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS security_validation_jobs_updated_at ON security_validation_jobs;
CREATE TRIGGER security_validation_jobs_updated_at
BEFORE UPDATE ON security_validation_jobs
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS remediation_actions_updated_at ON remediation_actions;
CREATE TRIGGER remediation_actions_updated_at
BEFORE UPDATE ON remediation_actions
FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DROP TRIGGER IF EXISTS threat_models_updated_at ON threat_models;
CREATE TRIGGER threat_models_updated_at
BEFORE UPDATE ON threat_models
FOR EACH ROW EXECUTE FUNCTION update_updated_at();
