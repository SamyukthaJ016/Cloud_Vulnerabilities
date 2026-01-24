-- =============================================================================
-- 03_init.sql
-- Purpose:
-- - Extensions
-- - Compatibility helpers
-- - Safe post-schema additions
-- MUST NOT redefine core tables
-- =============================================================================

-- ---------------------------------------------------
-- EXTENSIONS
-- ---------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ---------------------------------------------------
-- OPTIONAL: COMPATIBILITY VIEWS (for old backend code)
-- ---------------------------------------------------

-- Example: backward compatibility for old column name
-- (Only keep if your backend expects this)
-- CREATE OR REPLACE VIEW scans_compat AS
-- SELECT
--     id,
--     account_id,
--     cloud,
--     status,
--     started_at,
--     completed_at,
--     metadata AS scan_metadata
-- FROM scans;

-- ---------------------------------------------------
-- OPTIONAL: SAFE INDEX ADDITIONS
-- (Only if missing in 02_schema.sql)
-- ---------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_scans_account_id
ON scans(account_id);


-- CREATE INDEX IF NOT EXISTS idx_scans_account_id
--     ON scans(account_id);

-- ---------------------------------------------------
-- OPTIONAL: FUTURE SAFE MIGRATIONS
-- (Examples – keep commented until needed)
-- ---------------------------------------------------

-- ALTER TABLE resources
-- ADD COLUMN IF NOT EXISTS external_id VARCHAR(255);

-- ALTER TABLE findings
-- ADD COLUMN IF NOT EXISTS source_rule_id VARCHAR(255);

-- ---------------------------------------------------
-- NO TABLE CREATION HERE
-- NO DROPS HERE
-- NO FOREIGN KEYS HERE
-- ---------------------------------------------------

DO $$
BEGIN
    RAISE NOTICE '✅ 03_init.sql applied successfully (safe mode)';
END $$;
