#!/usr/bin/env python3
"""Re-enrich all attacker profiles with latest geo pipeline (run inside threat-engine container)."""

from __future__ import annotations

import asyncio
import json
import os

import asyncpg
import redis.asyncio as aioredis

from enrichment import enrich_ip


INTEL_DATABASE_URL = os.getenv(
    "INTEL_DATABASE_URL",
    "postgresql://honeypot:honeypot_secret@postgres-intel:5432/threat_intel",
)
REDIS_PLATFORM_URL = os.getenv("REDIS_PLATFORM_URL", "redis://:changeme_redis_local@redis-platform:6379/0")


async def main() -> None:
    pool = await asyncpg.create_pool(INTEL_DATABASE_URL, min_size=1, max_size=2)
    redis = aioredis.from_url(REDIS_PLATFORM_URL, decode_responses=True)

    async with pool.acquire() as conn:
        rows = await conn.fetch("SELECT host(ip) AS ip FROM attacker_profiles ORDER BY ip")

    updated = 0
    for row in rows:
        ip = row["ip"]
        geo = await enrich_ip(ip, redis)
        payload = geo.to_dict()
        if not geo.is_mappable() and geo.source == "private":
            continue

        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE attacker_profiles SET
                    geo_country = $2,
                    geo_country_code = $3,
                    geo_continent = $4,
                    geo_region = $5,
                    geo_city = $6,
                    geo_postal_code = $7,
                    geo_latitude = $8,
                    geo_longitude = $9,
                    geo_accuracy_km = $10,
                    geo_timezone = $11,
                    geo_asn = COALESCE($12, geo_asn),
                    geo_isp = COALESCE($13, geo_isp),
                    metadata = metadata || $14::jsonb
                WHERE ip = $1::inet
                """,
                ip,
                payload.get("geo_country"),
                payload.get("geo_country_code"),
                payload.get("geo_continent"),
                payload.get("geo_region"),
                payload.get("geo_city"),
                payload.get("geo_postal_code"),
                payload.get("geo_latitude"),
                payload.get("geo_longitude"),
                payload.get("geo_accuracy_km"),
                payload.get("geo_timezone"),
                payload.get("geo_asn"),
                payload.get("geo_isp"),
                json.dumps({
                    "geo_source": payload.get("geo_source"),
                    "geo_country_code": payload.get("geo_country_code"),
                    "geo_continent": payload.get("geo_continent"),
                    "geo_region": payload.get("geo_region"),
                    "geo_postal_code": payload.get("geo_postal_code"),
                    "geo_accuracy_km": payload.get("geo_accuracy_km"),
                    "geo_timezone": payload.get("geo_timezone"),
                }),
            )
        updated += 1
        print(f"{ip} → {payload.get('geo_city')}, {payload.get('geo_country')} ({payload.get('geo_source')}) ±{payload.get('geo_accuracy_km')}km")

    await redis.aclose()
    await pool.close()
    print(f"Re-enriched {updated} profiles")


if __name__ == "__main__":
    asyncio.run(main())