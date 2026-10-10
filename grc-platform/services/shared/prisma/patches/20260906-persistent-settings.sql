-- Upgrade an existing GRC schema before deploying the persistent settings services.
-- Fresh installations use schema.prisma. This patch preserves existing rows and
-- can be applied repeatedly with psql -v ON_ERROR_STOP=1 -f <this-file>.
BEGIN;

ALTER TABLE custom_field_definitions ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE custom_field_values ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE user_delegations ADD COLUMN IF NOT EXISTS scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'draft';
ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS created_by TEXT;
ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS next_run_at TIMESTAMP(3);

-- The API supports multiple policies for an entity type (for different filters).
DROP INDEX IF EXISTS retention_policies_organization_id_entity_type_key;
CREATE INDEX IF NOT EXISTS retention_policies_organization_id_entity_type_idx
    ON retention_policies (organization_id, entity_type);

COMMIT;
