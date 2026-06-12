"""Event, chain, timeline, heatmap, and map routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query

from app.deps import (
    _attach_classifications,
    _geo_source_from_row,
    _row_to_dict,
    get_events_pool,
    get_intel_pool,
    require_auth,
)

router = APIRouter()


@router.get("/events", dependencies=[Depends(require_auth)])
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    ip: str | None = None,
    service: str | None = None,
    q: str | None = None,
):
    clauses = []
    params: list[Any] = []
    idx = 1
    if ip:
        clauses.append(f"ip = ${idx}::inet")
        params.append(ip)
        idx += 1
    if service:
        clauses.append(f"service = ${idx}")
        params.append(service)
        idx += 1
    if q:
        clauses.append(f"(endpoint ILIKE ${idx} OR user_agent ILIKE ${idx})")
        params.append(f"%{q}%")
        idx += 1
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])

    async with get_events_pool().acquire() as events_conn:
        rows = await events_conn.fetch(
            f"""
            SELECT id, service, host(ip) AS ip, method, endpoint, payload, user_agent, status_code, created_at
            FROM events {where} ORDER BY created_at DESC LIMIT ${idx} OFFSET ${idx + 1}
            """,
            *params,
        )
        events = [_row_to_dict(r) for r in rows]
    async with get_intel_pool().acquire() as intel_conn:
        return await _attach_classifications(intel_conn, events)


@router.get("/chains", dependencies=[Depends(require_auth)])
async def list_chains(limit: int = Query(30, ge=1, le=100)):
    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, host(ip) AS ip, services, chain_summary, risk_score,
                   started_at, last_activity
            FROM attack_chains ORDER BY last_activity DESC LIMIT $1
            """,
            limit,
        )
    return [_row_to_dict(r) for r in rows]


@router.get("/timeline", dependencies=[Depends(require_auth)])
async def attack_timeline(hours: int = Query(24, ge=1, le=168)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    async with get_events_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT date_trunc('hour', created_at) AS bucket,
                   COUNT(*) AS count,
                   COUNT(DISTINCT ip) AS unique_ips
            FROM events WHERE created_at > $1
            GROUP BY bucket ORDER BY bucket ASC
            """,
            since,
        )
    return [_row_to_dict(r) for r in rows]


@router.get("/heatmap", dependencies=[Depends(require_auth)])
async def threat_heatmap(hours: int = Query(24, ge=1, le=168)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT date_trunc('hour', created_at) AS bucket,
                   classification,
                   COUNT(*) AS count
            FROM threat_classifications
            WHERE created_at > $1
            GROUP BY bucket, classification
            ORDER BY bucket ASC
            """,
            since,
        )
    return [_row_to_dict(r) for r in rows]


@router.get("/map", dependencies=[Depends(require_auth)])
async def threat_map():
    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT host(ip) AS ip, risk_score, behavior_tags, total_requests, last_seen,
                   geo_country, geo_country_code, geo_continent, geo_region, geo_city, geo_postal_code,
                   geo_latitude, geo_longitude, geo_accuracy_km, geo_timezone,
                   geo_asn, geo_isp, metadata
            FROM attacker_profiles
            WHERE risk_score >= 10
              AND geo_latitude IS NOT NULL
              AND geo_longitude IS NOT NULL
              AND COALESCE(metadata->>'geo_source', '') IN ('maxmind', 'ipapi')
            ORDER BY risk_score DESC LIMIT 200
            """,
        )
    result = []
    for r in rows:
        d = _row_to_dict(r)
        d["geo_source"] = _geo_source_from_row(r)
        result.append(d)
    return result