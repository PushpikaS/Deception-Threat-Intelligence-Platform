"""ASN rollup — aggregated from GeoIP enrichment and honeypot risk scores."""

from __future__ import annotations

import json
from typing import Any

import asyncpg


async def upsert_asn_intel(
    conn: asyncpg.Connection,
    geo: dict[str, Any],
    risk: int,
    *,
    prev_asn: str | None = None,
) -> None:
    asn = geo.get("geo_asn")
    if not asn:
        return

    high_risk_hit = 1 if risk >= 60 else 0
    new_ip_for_asn = prev_asn != asn

    await conn.execute(
        """
        INSERT INTO asn_intel (asn, org, country_code, ip_count, event_count, avg_risk_score, max_risk_score, malicious_hits, metadata)
        VALUES ($1, $2, $3, $4, 1, $5, $5, $6, $7::jsonb)
        ON CONFLICT (asn) DO UPDATE SET
            org = COALESCE(EXCLUDED.org, asn_intel.org),
            country_code = COALESCE(EXCLUDED.country_code, asn_intel.country_code),
            ip_count = asn_intel.ip_count + EXCLUDED.ip_count,
            event_count = asn_intel.event_count + 1,
            avg_risk_score = ((asn_intel.avg_risk_score * asn_intel.event_count) + EXCLUDED.avg_risk_score)
                             / (asn_intel.event_count + 1),
            max_risk_score = GREATEST(asn_intel.max_risk_score, EXCLUDED.max_risk_score),
            malicious_hits = asn_intel.malicious_hits + EXCLUDED.malicious_hits,
            metadata = asn_intel.metadata || EXCLUDED.metadata,
            updated_at = NOW()
        """,
        asn,
        geo.get("geo_isp"),
        geo.get("geo_country_code"),
        1 if new_ip_for_asn else 0,
        risk,
        high_risk_hit,
        json.dumps({"last_isp": geo.get("geo_isp")}),
    )