CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    service     VARCHAR(64)  NOT NULL,
    ip          INET         NOT NULL,
    method      VARCHAR(16)  NOT NULL,
    endpoint    TEXT         NOT NULL,
    payload     JSONB        DEFAULT '{}',
    user_agent  TEXT,
    status_code SMALLINT     DEFAULT 200,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (ip);
CREATE INDEX IF NOT EXISTS idx_events_service ON events (service);
CREATE INDEX IF NOT EXISTS idx_events_ip_created ON events (ip, created_at DESC);