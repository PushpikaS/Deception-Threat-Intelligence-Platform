"""Additive schema migrations for existing intel DB volumes."""

from __future__ import annotations

import asyncpg

MIGRATION_SQL = """
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS geo_continent VARCHAR(32);
ALTER TABLE attacker_profiles ADD COLUMN IF NOT EXISTS geo_postal_code VARCHAR(16);

CREATE TABLE IF NOT EXISTS asn_intel (
    asn VARCHAR(32) PRIMARY KEY,
    org VARCHAR(256),
    country_code CHAR(2),
    ip_count INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0,
    avg_risk_score SMALLINT NOT NULL DEFAULT 0,
    max_risk_score SMALLINT NOT NULL DEFAULT 0,
    malicious_hits INTEGER NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def ensure_intel_schema(conn: asyncpg.Connection) -> None:
    await conn.execute(MIGRATION_SQL)