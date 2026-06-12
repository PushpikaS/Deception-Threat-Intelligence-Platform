"""Attacker profile routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from app.deps import _attach_classifications, _row_to_dict, get_events_pool, get_intel_pool, require_auth

router = APIRouter()


@router.get("/profiles/search", dependencies=[Depends(require_auth)])
async def search_profiles(
    q: str | None = None,
    min_risk: int = Query(0, ge=0, le=100),
    country: str | None = None,
    tag: str | None = None,
    sort: str = Query("risk", pattern="^(risk|requests|last_seen)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    clauses = ["risk_score >= $1"]
    params: list[Any] = [min_risk]
    idx = 2

    if q:
        clauses.append(f"(host(ip) ILIKE ${idx} OR geo_city ILIKE ${idx} OR geo_isp ILIKE ${idx})")
        params.append(f"%{q}%")
        idx += 1
    if country:
        clauses.append(f"geo_country ILIKE ${idx}")
        params.append(country)
        idx += 1
    if tag:
        clauses.append(f"${idx} = ANY(behavior_tags)")
        params.append(tag)
        idx += 1

    order = {
        "risk": "risk_score DESC, last_seen DESC",
        "requests": "total_requests DESC",
        "last_seen": "last_seen DESC",
    }[sort]

    where = " AND ".join(clauses)
    params.extend([limit, offset])

    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, host(ip) AS ip, risk_score, behavior_tags, total_requests,
                   first_seen, last_seen, geo_country, geo_country_code, geo_continent,
                   geo_region, geo_city, geo_postal_code, geo_latitude, geo_longitude,
                   geo_accuracy_km, geo_timezone, geo_asn, geo_isp, metadata
            FROM attacker_profiles WHERE {where}
            ORDER BY {order} LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
        )
    return [_row_to_dict(r) for r in rows]


@router.get("/profiles/{ip}", dependencies=[Depends(require_auth)])
async def get_profile(ip: str):
    async with get_intel_pool().acquire() as intel_conn:
        profile = await intel_conn.fetchrow(
            """
            SELECT id, host(ip) AS ip, risk_score, behavior_tags, total_requests,
                   first_seen, last_seen, geo_country, geo_country_code, geo_continent,
                   geo_region, geo_city, geo_postal_code, geo_latitude, geo_longitude,
                   geo_accuracy_km, geo_timezone, geo_asn, geo_isp, metadata
            FROM attacker_profiles WHERE ip = $1::inet
            """,
            ip,
        )
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        classifications = await intel_conn.fetch(
            """
            SELECT event_id, classification, confidence, details, created_at
            FROM threat_classifications WHERE ip = $1::inet ORDER BY created_at DESC LIMIT 20
            """,
            ip,
        )
        async with get_events_pool().acquire() as events_conn:
            events = await events_conn.fetch(
                """
                SELECT id, service, method, endpoint, status_code, created_at
                FROM events WHERE ip = $1::inet ORDER BY created_at DESC LIMIT 50
                """,
                ip,
            )
            event_rows = [_row_to_dict(e) for e in events]
        event_rows = await _attach_classifications(intel_conn, event_rows)
    clf_rows = []
    for c in classifications:
        row = _row_to_dict(c)
        details = row.get("details") or {}
        row["mitre"] = details.get("mitre") or []
        clf_rows.append(row)
    return {
        "profile": _row_to_dict(profile),
        "events": event_rows,
        "classifications": clf_rows,
    }


@router.get("/profiles/{ip}/timeline", dependencies=[Depends(require_auth)])
async def profile_timeline(ip: str, hours: int = Query(48, ge=1, le=168)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    async with get_events_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT date_trunc('hour', created_at) AS bucket, COUNT(*) AS count
            FROM events WHERE ip = $1::inet AND created_at > $2
            GROUP BY bucket ORDER BY bucket ASC
            """,
            ip,
            since,
        )
    return [_row_to_dict(r) for r in rows]