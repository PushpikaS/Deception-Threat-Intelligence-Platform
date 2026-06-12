"""Statistics and global search routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from app.deps import _cached, _row_to_dict, get_events_pool, get_intel_pool, require_auth

router = APIRouter()


@router.get("/stats/trends", dependencies=[Depends(require_auth)])
async def stats_trends():
    async def fetch():
        now = datetime.now(timezone.utc)
        async with get_events_pool().acquire() as events_conn:
            week = await events_conn.fetchrow(
                """
                SELECT COUNT(*) FILTER (WHERE created_at > $1) AS events_7d,
                       COUNT(*) FILTER (WHERE created_at BETWEEN $2 AND $1) AS events_prev_7d,
                       COUNT(DISTINCT ip) FILTER (WHERE created_at > $1) AS ips_7d
                FROM events
                """,
                now - timedelta(days=7),
                now - timedelta(days=14),
            )
            month = await events_conn.fetchval(
                "SELECT COUNT(*) FROM events WHERE created_at > $1",
                now - timedelta(days=30),
            )
        async with get_intel_pool().acquire() as intel_conn:
            risk = await intel_conn.fetchrow(
                """
                SELECT COUNT(*) FILTER (WHERE risk_score >= 60 AND last_seen > $1) AS high_risk_7d,
                       COUNT(*) FILTER (WHERE risk_score >= 60 AND last_seen BETWEEN $2 AND $1) AS high_risk_prev_7d
                FROM attacker_profiles
                """,
                now - timedelta(days=7),
                now - timedelta(days=14),
            )
        return {
            "events_7d": week["events_7d"],
            "events_prev_7d": week["events_prev_7d"],
            "events_30d": month,
            "unique_ips_7d": week["ips_7d"],
            "high_risk_7d": risk["high_risk_7d"],
            "high_risk_prev_7d": risk["high_risk_prev_7d"],
        }

    return await _cached("cache:stats:trends", fetch)


@router.get("/search", dependencies=[Depends(require_auth)])
async def global_search(q: str = Query(..., min_length=1), limit: int = Query(20, ge=1, le=100)):
    pattern = f"%{q}%"
    async with get_intel_pool().acquire() as intel_conn:
        profiles = await intel_conn.fetch(
            """
            SELECT host(ip) AS ip, risk_score, behavior_tags, geo_country, last_seen
            FROM attacker_profiles
            WHERE host(ip) ILIKE $1 OR geo_country ILIKE $1 OR geo_city ILIKE $1
               OR EXISTS (SELECT 1 FROM unnest(behavior_tags) t WHERE t ILIKE $1)
            ORDER BY risk_score DESC LIMIT $2
            """,
            pattern,
            limit,
        )
        classifications = await intel_conn.fetch(
            """
            SELECT DISTINCT classification, host(ip) AS ip, MAX(created_at) AS last_seen
            FROM threat_classifications
            WHERE classification ILIKE $1 OR host(ip) ILIKE $1
            GROUP BY classification, ip ORDER BY last_seen DESC LIMIT $2
            """,
            pattern,
            limit,
        )
    async with get_events_pool().acquire() as events_conn:
        events = await events_conn.fetch(
            """
            SELECT id, service, host(ip) AS ip, method, endpoint, created_at
            FROM events
            WHERE host(ip) ILIKE $1 OR endpoint ILIKE $1 OR service ILIKE $1
            ORDER BY created_at DESC LIMIT $2
            """,
            pattern,
            limit,
        )
    return {
        "profiles": [_row_to_dict(r) for r in profiles],
        "events": [_row_to_dict(r) for r in events],
        "classifications": [_row_to_dict(r) for r in classifications],
    }


@router.get("/stats/overview", dependencies=[Depends(require_auth)])
async def stats_overview():
    async def fetch():
        async with get_events_pool().acquire() as events_conn:
            total_events = await events_conn.fetchval("SELECT COUNT(*) FROM events")
            last_hour = await events_conn.fetchval(
                "SELECT COUNT(*) FROM events WHERE created_at > NOW() - INTERVAL '1 hour'"
            )
            by_service = await events_conn.fetch(
                "SELECT service, COUNT(*) AS count FROM events GROUP BY service ORDER BY count DESC"
            )
        async with get_intel_pool().acquire() as intel_conn:
            total_profiles = await intel_conn.fetchval("SELECT COUNT(*) FROM attacker_profiles")
            high_risk = await intel_conn.fetchval(
                "SELECT COUNT(*) FROM attacker_profiles WHERE risk_score >= 60"
            )
            by_class = await intel_conn.fetch(
                """
                SELECT classification, COUNT(*) AS count FROM threat_classifications
                WHERE created_at > NOW() - INTERVAL '24 hours'
                GROUP BY classification ORDER BY count DESC LIMIT 15
                """
            )
            by_country = await intel_conn.fetch(
                """
                SELECT geo_country, COUNT(*) AS count FROM attacker_profiles
                WHERE geo_country IS NOT NULL
                GROUP BY geo_country ORDER BY count DESC LIMIT 10
                """
            )
        return {
            "total_events": total_events,
            "total_profiles": total_profiles,
            "high_risk_profiles": high_risk,
            "events_last_hour": last_hour,
            "by_service": [_row_to_dict(r) for r in by_service],
            "by_classification": [_row_to_dict(r) for r in by_class],
            "by_country": [_row_to_dict(r) for r in by_country],
        }

    return await _cached("cache:stats:overview", fetch)


@router.get("/stats/countries", dependencies=[Depends(require_auth)])
async def stats_countries(
    limit: int = Query(5, ge=1, le=20),
    hours: int = Query(24, ge=1, le=168),
):
    """Top attacking countries by event volume (production SOC metric)."""
    async with get_events_pool().acquire() as events_conn:
        event_rows = await events_conn.fetch(
            """
            SELECT host(ip) AS ip, COUNT(*) AS event_count
            FROM events
            WHERE created_at > NOW() - make_interval(hours => $1)
            GROUP BY ip
            """,
            hours,
        )
    if not event_rows:
        return []

    ips = [r["ip"] for r in event_rows]
    counts = {r["ip"]: r["event_count"] for r in event_rows}

    async with get_intel_pool().acquire() as intel_conn:
        profiles = await intel_conn.fetch(
            """
            SELECT host(ip) AS ip, geo_country, geo_country_code, risk_score
            FROM attacker_profiles WHERE host(ip) = ANY($1::text[])
            """,
            ips,
        )

    profile_map = {r["ip"]: dict(r) for r in profiles}
    agg: dict[str, dict] = {}
    for ip, ec in counts.items():
        p = profile_map.get(ip, {})
        code = p.get("geo_country_code") or p.get("geo_country") or "Unknown"
        country = p.get("geo_country") or "Unknown"
        key = code
        risk = int(p.get("risk_score") or 0)
        if key not in agg:
            agg[key] = {
                "country_code": code,
                "country": country,
                "event_count": 0,
                "unique_ips": 0,
                "max_risk": 0,
                "avg_risk": 0,
                "risk_sum": 0,
                "high_risk_ips": 0,
            }
        agg[key]["event_count"] += ec
        agg[key]["unique_ips"] += 1
        agg[key]["max_risk"] = max(agg[key]["max_risk"], risk)
        agg[key]["risk_sum"] += risk
        if risk >= 60:
            agg[key]["high_risk_ips"] += 1

    ranked = sorted(agg.values(), key=lambda x: x["event_count"], reverse=True)
    total_events = sum(r["event_count"] for r in ranked) or 1
    for r in ranked:
        r["avg_risk"] = round(r["risk_sum"] / r["unique_ips"]) if r["unique_ips"] else 0
        del r["risk_sum"]
        r["share_percent"] = round(100 * r["event_count"] / total_events)
    return ranked[:limit]


@router.get("/stats/asn", dependencies=[Depends(require_auth)])
async def stats_asn(limit: int = Query(10, ge=1, le=50)):
    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT asn, org, country_code, ip_count, event_count,
                   avg_risk_score, max_risk_score, malicious_hits, updated_at
            FROM asn_intel ORDER BY avg_risk_score DESC, event_count DESC LIMIT $1
            """,
            limit,
        )
    return [_row_to_dict(r) for r in rows]