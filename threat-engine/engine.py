"""Continuous threat engine — batch classification, geo enrichment, risk scoring."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import time
import asyncpg
import redis.asyncio as aioredis

from chains import build_chain_summary
from asn_intel import upsert_asn_intel
from classifier import (
    behavior_tags,
    classify_event_local,
    classify_profile_context,
    compute_risk_score,
    request_velocity,
)
from enrichment import close_readers, enrich_ip, merge_geo_profiles
from migrate import ensure_intel_schema
from shared_mitre import mitre_for_classification, mitre_for_classifications
from shared_production_check import assert_production_safe

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","svc":"threat-engine","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger(__name__)

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "2"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
EVENTS_DATABASE_URL = os.getenv(
    "EVENTS_DATABASE_URL",
    "postgresql://honeypot:honeypot_secret@localhost:5432/honeypot_events",
)
INTEL_DATABASE_URL = os.getenv(
    "INTEL_DATABASE_URL",
    "postgresql://honeypot:honeypot_secret@localhost:5432/threat_intel",
)
REDIS_PLATFORM_URL = os.getenv("REDIS_PLATFORM_URL", "redis://localhost:6379/0")
CACHE_TTL = int(os.getenv("CACHE_TTL", "30"))

running = True


def _stop(*_):
    global running
    running = False


LIVE_CHANNEL = "tip:live"


async def publish_live(redis: aioredis.Redis, payload: dict) -> None:
    try:
        await redis.publish(LIVE_CHANNEL, json.dumps(payload, default=str))
    except Exception:
        pass


async def get_last_processed(conn: asyncpg.Connection) -> int:
    row = await conn.fetchrow("SELECT value FROM engine_state WHERE key = 'last_processed_event_id'")
    return int(row["value"]) if row else 0


async def set_last_processed(conn: asyncpg.Connection, event_id: int) -> None:
    await conn.execute(
        """
        INSERT INTO engine_state (key, value, updated_at) VALUES ('last_processed_event_id', $1, NOW())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        """,
        str(event_id),
    )


async def fetch_recent_for_ip(conn: asyncpg.Connection, ip: str, limit: int = 50) -> list[dict]:
    rows = await conn.fetch(
        """
        SELECT id, service, host(ip) AS ip, method, endpoint, payload, user_agent, status_code, created_at
        FROM events WHERE ip = $1::inet
        ORDER BY created_at DESC LIMIT $2
        """,
        ip,
        limit,
    )
    return [dict(r) for r in rows]


async def get_previous_profile(conn: asyncpg.Connection, ip: str) -> dict | None:
    row = await conn.fetchrow(
        """
        SELECT risk_score, last_seen, metadata, geo_country, geo_city,
               geo_latitude, geo_longitude, geo_asn, geo_isp
        FROM attacker_profiles WHERE ip = $1::inet
        """,
        ip,
    )
    return dict(row) if row else None


async def upsert_profile(
    conn: asyncpg.Connection,
    ip: str,
    risk: int,
    tags: list[str],
    geo: dict,
    metadata: dict,
) -> None:
    await conn.execute(
        """
        INSERT INTO attacker_profiles (
            ip, risk_score, behavior_tags, total_requests, first_seen, last_seen,
            geo_country, geo_country_code, geo_continent, geo_region, geo_city, geo_postal_code,
            geo_latitude, geo_longitude, geo_accuracy_km, geo_timezone,
            geo_asn, geo_isp, metadata
        )
        VALUES ($1::inet, $2, $3, 1, NOW(), NOW(), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb)
        ON CONFLICT (ip) DO UPDATE SET
            risk_score = GREATEST(attacker_profiles.risk_score, EXCLUDED.risk_score),
            behavior_tags = (
                SELECT ARRAY(SELECT DISTINCT unnest(attacker_profiles.behavior_tags || EXCLUDED.behavior_tags))
            ),
            total_requests = attacker_profiles.total_requests + 1,
            last_seen = NOW(),
            geo_country = EXCLUDED.geo_country,
            geo_country_code = EXCLUDED.geo_country_code,
            geo_continent = EXCLUDED.geo_continent,
            geo_region = EXCLUDED.geo_region,
            geo_city = EXCLUDED.geo_city,
            geo_postal_code = EXCLUDED.geo_postal_code,
            geo_latitude = EXCLUDED.geo_latitude,
            geo_longitude = EXCLUDED.geo_longitude,
            geo_accuracy_km = EXCLUDED.geo_accuracy_km,
            geo_timezone = EXCLUDED.geo_timezone,
            geo_asn = COALESCE(EXCLUDED.geo_asn, attacker_profiles.geo_asn),
            geo_isp = COALESCE(EXCLUDED.geo_isp, attacker_profiles.geo_isp),
            metadata = attacker_profiles.metadata || EXCLUDED.metadata
        """,
        ip,
        risk,
        tags,
        geo.get("geo_country"),
        geo.get("geo_country_code"),
        geo.get("geo_continent"),
        geo.get("geo_region"),
        geo.get("geo_city"),
        geo.get("geo_postal_code"),
        geo.get("geo_latitude"),
        geo.get("geo_longitude"),
        geo.get("geo_accuracy_km"),
        geo.get("geo_timezone"),
        geo.get("geo_asn"),
        geo.get("geo_isp"),
        json.dumps(metadata),
    )


async def upsert_attack_chain(
    conn: asyncpg.Connection,
    ip: str,
    services: set[str],
    risk: int,
    classifications: list[str],
    endpoints: list[str],
) -> None:
    svc_list = sorted(services)
    if len(svc_list) < 2:
        return

    existing = await conn.fetchrow(
        "SELECT id, services FROM attack_chains WHERE ip = $1::inet ORDER BY last_activity DESC LIMIT 1",
        ip,
    )
    summary = build_chain_summary(svc_list, classifications, endpoints)

    if existing:
        merged = sorted(set(existing["services"]) | services)
        await conn.execute(
            """
            UPDATE attack_chains SET services = $2, chain_summary = $3,
                risk_score = GREATEST(risk_score, $4), last_activity = NOW()
            WHERE id = $1
            """,
            existing["id"],
            merged,
            summary,
            risk,
        )
    else:
        await conn.execute(
            """
            INSERT INTO attack_chains (ip, services, chain_summary, risk_score, started_at, last_activity)
            VALUES ($1::inet, $2, $3, $4, NOW(), NOW())
            """,
            ip,
            svc_list,
            summary,
            risk,
        )


async def cache_profile(redis: aioredis.Redis, ip: str, risk: int, tags: list[str], geo: dict) -> None:
    payload = json.dumps({"ip": ip, "risk_score": risk, "behavior_tags": tags, **geo})
    await redis.setex(f"profile:{ip}", CACHE_TTL, payload)
    await redis.delete("cache:stats:overview", "cache:stats:trends")


async def process_batch(
    events_conn: asyncpg.Connection,
    intel_conn: asyncpg.Connection,
    redis: aioredis.Redis,
) -> int:
    last_id = await get_last_processed(intel_conn)
    rows = await events_conn.fetch(
        """
        SELECT id, service, host(ip) AS ip, method, endpoint, payload, user_agent, status_code, created_at
        FROM events WHERE id > $1 ORDER BY id ASC LIMIT $2
        """,
        last_id,
        BATCH_SIZE,
    )
    if not rows:
        return 0

    max_id = last_id
    geo_cache: dict[str, dict] = {}
    recent_cache: dict[str, list[dict]] = {}
    profile_cache: dict[str, dict | None] = {}
    async with intel_conn.transaction():
        for row in rows:
            event = dict(row)
            if isinstance(event.get("payload"), str):
                event["payload"] = json.loads(event["payload"])

            ip = event["ip"]
            if ip not in recent_cache:
                recent_cache[ip] = await fetch_recent_for_ip(events_conn, ip)
            recent = recent_cache[ip]
            local_clfs = classify_event_local(event)
            context_clfs = classify_profile_context(event, recent)
            all_clfs = local_clfs + context_clfs
            clf_names = [c.name for c in all_clfs]
            mitre = mitre_for_classifications(clf_names)

            for clf in local_clfs:
                details = {**clf.details, "mitre": mitre_for_classification(clf.name), "scope": "event"}
                await intel_conn.execute(
                    """
                    INSERT INTO threat_classifications (event_id, ip, classification, confidence, details)
                    VALUES ($1, $2::inet, $3, $4, $5::jsonb)
                    ON CONFLICT (event_id, classification) DO NOTHING
                    """,
                    event["id"],
                    ip,
                    clf.name,
                    clf.confidence,
                    json.dumps(details),
                )

            if ip not in profile_cache:
                profile_cache[ip] = await get_previous_profile(intel_conn, ip)
            prev = profile_cache[ip]

            if ip not in geo_cache:
                geo_info = await enrich_ip(ip, redis)
                new_geo = geo_info.to_dict()
                geo_cache[ip] = merge_geo_profiles(prev, new_geo)

            prev_score = prev["risk_score"] if prev else 0
            prev_seen = prev["last_seen"] if prev else None
            velocity = request_velocity(recent, ip)

            total = len(recent) + 1
            geo = geo_cache[ip]

            risk = compute_risk_score(
                all_clfs, total,
                last_seen=prev_seen,
                velocity=velocity,
                previous_score=prev_score,
            )
            tags = behavior_tags(all_clfs)
            context_payload = [
                {
                    "classification": c.name,
                    "confidence": c.confidence,
                    "details": c.details,
                    "mitre": mitre_for_classification(c.name),
                }
                for c in context_clfs
            ]
            metadata = {
                "mitre_techniques": mitre,
                "context_classifications": context_payload,
                "context_mitre_techniques": mitre_for_classifications([c.name for c in context_clfs]),
                "geo_source": geo.get("geo_source", "unknown"),
                "geo_country_code": geo.get("geo_country_code"),
                "geo_continent": geo.get("geo_continent"),
                "geo_region": geo.get("geo_region"),
                "geo_postal_code": geo.get("geo_postal_code"),
                "geo_accuracy_km": geo.get("geo_accuracy_km"),
                "geo_timezone": geo.get("geo_timezone"),
            }

            await upsert_profile(intel_conn, ip, risk, tags, geo, metadata)
            await cache_profile(redis, ip, risk, tags, geo)
            await upsert_asn_intel(
                intel_conn,
                geo,
                risk,
                prev_asn=prev.get("geo_asn") if prev else None,
            )

            services = {event["service"]} | {e["service"] for e in recent}
            ep_list = [event["endpoint"]] + [e.get("endpoint", "") for e in recent]
            await upsert_attack_chain(intel_conn, ip, services, risk, clf_names, ep_list)

            await publish_live(redis, {
                "type": "event_processed",
                "event_id": event["id"],
                "ip": ip,
                "risk_score": risk,
                "service": event["service"],
                "endpoint": event["endpoint"],
                "classifications": clf_names,
            })

            max_id = event["id"]

        await set_last_processed(intel_conn, max_id)
    return len(rows)


async def main() -> None:
    assert_production_safe()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    events_pool = await asyncpg.create_pool(EVENTS_DATABASE_URL, min_size=2, max_size=6)
    intel_pool = await asyncpg.create_pool(INTEL_DATABASE_URL, min_size=2, max_size=8)
    redis = aioredis.from_url(REDIS_PLATFORM_URL, decode_responses=True)

    async with intel_pool.acquire() as conn:
        await ensure_intel_schema(conn)

    log.info("Threat engine started poll=%ss batch=%d (classify + profile)", POLL_INTERVAL, BATCH_SIZE)

    try:
        while running:
            async with events_pool.acquire() as events_conn, intel_pool.acquire() as intel_conn:
                classified = await process_batch(events_conn, intel_conn, redis)
                if classified:
                    log.info("Classified %d events", classified)
            await asyncio.sleep(POLL_INTERVAL)
    finally:
        close_readers()
        await redis.aclose()
        await events_pool.close()
        await intel_pool.close()
        log.info("Threat engine stopped")


if __name__ == "__main__":
    asyncio.run(main())