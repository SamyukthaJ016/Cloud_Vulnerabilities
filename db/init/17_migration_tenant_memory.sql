-- Tenant-scoped AI memory. Legacy records remain unassigned and invisible.
CREATE TABLE IF NOT EXISTS finding_memory (
                            id SERIAL PRIMARY KEY,
                            finding_hash VARCHAR(64) UNIQUE NOT NULL,
                            first_seen TIMESTAMP NOT NULL,
                            last_seen TIMESTAMP NOT NULL,
                            occurrence_count INTEGER DEFAULT 1,
                            resource_name VARCHAR(500),
                            provider VARCHAR(50),
                            issue TEXT,
                            severity VARCHAR(20),
                            status VARCHAR(50) DEFAULT 'new',
                            scan_ids JSONB DEFAULT '[]',
                            metadata JSONB DEFAULT '{}'
                        );

CREATE TABLE IF NOT EXISTS security_tasks (
                            id SERIAL PRIMARY KEY,
                            finding_id INTEGER REFERENCES findings(id),
                            finding_hash VARCHAR(64),
                            resource_name VARCHAR(500),
                            provider VARCHAR(50),
                            issue TEXT,
                            description TEXT,
                            recommendation TEXT,
                            priority VARCHAR(20),
                            status VARCHAR(50) DEFAULT 'open',
                            created_at TIMESTAMP DEFAULT NOW(),
                            updated_at TIMESTAMP DEFAULT NOW(),
                            resolved_at TIMESTAMP,
                            related_tasks JSONB DEFAULT '[]',
                            metadata JSONB DEFAULT '{}'
                        );

CREATE TABLE IF NOT EXISTS security_notes (
                            id SERIAL PRIMARY KEY,
                            finding_hash VARCHAR(64),
                            task_id INTEGER REFERENCES security_tasks(id),
                            note_type VARCHAR(50),
                            content TEXT,
                            author VARCHAR(200) DEFAULT 'system',
                            created_at TIMESTAMP DEFAULT NOW(),
                            tags JSONB DEFAULT '[]'
                        );

CREATE TABLE IF NOT EXISTS security_knowledge (
                            id SERIAL PRIMARY KEY,
                            pattern_type VARCHAR(100),
                            pattern_data JSONB,
                            confidence FLOAT DEFAULT 0.5,
                            evidence_count INTEGER DEFAULT 1,
                            last_updated TIMESTAMP DEFAULT NOW(),
                            metadata JSONB DEFAULT '{}'
                        );
ALTER TABLE finding_memory ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE finding_memory ADD COLUMN IF NOT EXISTS user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_finding_memory_owner ON finding_memory(tenant_id, user_id);
ALTER TABLE security_tasks ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE security_tasks ADD COLUMN IF NOT EXISTS user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_security_tasks_owner ON security_tasks(tenant_id, user_id);
ALTER TABLE security_notes ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE security_notes ADD COLUMN IF NOT EXISTS user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_security_notes_owner ON security_notes(tenant_id, user_id);
ALTER TABLE security_knowledge ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(255);
ALTER TABLE security_knowledge ADD COLUMN IF NOT EXISTS user_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_security_knowledge_owner ON security_knowledge(tenant_id, user_id);
ALTER TABLE finding_memory ADD COLUMN IF NOT EXISTS account_id TEXT NOT NULL DEFAULT '';
