CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS attacker_profiles (
    id              BIGSERIAL PRIMARY KEY,
    ip              INET         NOT NULL UNIQUE,
    risk_score      SMALLINT     NOT NULL DEFAULT 0,
    behavior_tags   TEXT[]       NOT NULL DEFAULT '{}',
    total_requests  INTEGER      NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    geo_country     VARCHAR(64),
    geo_country_code CHAR(2),
    geo_continent   VARCHAR(32),
    geo_region      VARCHAR(128),
    geo_city        VARCHAR(128),
    geo_postal_code VARCHAR(16),
    geo_latitude    DOUBLE PRECISION,
    geo_longitude   DOUBLE PRECISION,
    geo_accuracy_km SMALLINT,
    geo_timezone    VARCHAR(64),
    geo_asn         VARCHAR(32),
    geo_isp         VARCHAR(256),
    metadata        JSONB        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_profiles_risk ON attacker_profiles (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_last_seen ON attacker_profiles (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_profiles_country ON attacker_profiles (geo_country);
CREATE INDEX IF NOT EXISTS idx_profiles_geo ON attacker_profiles (geo_latitude, geo_longitude) WHERE geo_latitude IS NOT NULL;

-- event_id references the events service (no cross-database FK)
CREATE TABLE IF NOT EXISTS threat_classifications (
    id              BIGSERIAL PRIMARY KEY,
    event_id        BIGINT       NOT NULL,
    ip              INET         NOT NULL,
    classification  VARCHAR(64)  NOT NULL,
    confidence      REAL         NOT NULL DEFAULT 0.5,
    details         JSONB        NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_classifications_ip ON threat_classifications (ip);
CREATE INDEX IF NOT EXISTS idx_classifications_event_id ON threat_classifications (event_id);
CREATE INDEX IF NOT EXISTS idx_classifications_type ON threat_classifications (classification);
CREATE INDEX IF NOT EXISTS idx_classifications_created ON threat_classifications (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_classifications_event_type ON threat_classifications (event_id, classification);

CREATE TABLE IF NOT EXISTS attack_chains (
    id              BIGSERIAL PRIMARY KEY,
    ip              INET         NOT NULL,
    services        TEXT[]       NOT NULL DEFAULT '{}',
    chain_summary   TEXT,
    risk_score      SMALLINT     NOT NULL DEFAULT 0,
    started_at      TIMESTAMPTZ  NOT NULL,
    last_activity   TIMESTAMPTZ  NOT NULL,
    metadata        JSONB        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_chains_ip ON attack_chains (ip);
CREATE INDEX IF NOT EXISTS idx_chains_last_activity ON attack_chains (last_activity DESC);

CREATE TABLE IF NOT EXISTS engine_state (
    key         VARCHAR(64) PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO engine_state (key, value) VALUES ('last_processed_event_id', '0')
ON CONFLICT (key) DO NOTHING;

-- ASN intelligence rollup (threat-engine writes, threat-api reads)
CREATE TABLE IF NOT EXISTS asn_intel (
    asn             VARCHAR(32) PRIMARY KEY,
    org             VARCHAR(256),
    country_code    CHAR(2),
    ip_count        INTEGER      NOT NULL DEFAULT 0,
    event_count     INTEGER      NOT NULL DEFAULT 0,
    avg_risk_score  SMALLINT     NOT NULL DEFAULT 0,
    max_risk_score  SMALLINT     NOT NULL DEFAULT 0,
    malicious_hits  INTEGER      NOT NULL DEFAULT 0,
    metadata        JSONB        NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asn_intel_risk ON asn_intel (avg_risk_score DESC);