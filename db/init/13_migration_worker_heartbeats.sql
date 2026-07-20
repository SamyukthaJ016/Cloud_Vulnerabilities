-- Migration: worker heartbeat tracking
--
-- Keeps scanner and connector availability visible to the portal while scan
-- jobs remain decoupled from the dashboard/API process.

CREATE TABLE IF NOT EXISTS scanner_worker_heartbeats (
    id SERIAL PRIMARY KEY,
    worker_id VARCHAR(128) UNIQUE NOT NULL,
    worker_type VARCHAR(64) NOT NULL DEFAULT 'scan',
    status VARCHAR(32) NOT NULL DEFAULT 'online',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_scanner_worker_type
        CHECK (worker_type IN ('scan','scheduler','sandbox','evidence','inline','unknown')),
    CONSTRAINT valid_scanner_worker_status
        CHECK (status IN ('online','idle','busy','degraded','offline'))
);

CREATE INDEX IF NOT EXISTS idx_scanner_worker_heartbeats_type_seen
ON scanner_worker_heartbeats (worker_type, last_seen_at DESC);

DROP TRIGGER IF EXISTS scanner_worker_heartbeats_updated_at ON scanner_worker_heartbeats;
CREATE TRIGGER scanner_worker_heartbeats_updated_at
BEFORE UPDATE ON scanner_worker_heartbeats
FOR EACH ROW EXECUTE FUNCTION update_updated_at();
