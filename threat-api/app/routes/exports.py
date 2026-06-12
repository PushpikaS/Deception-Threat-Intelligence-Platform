"""Export routes — STIX, CSV, and blocklist."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from app.deps import _attach_classifications, _row_to_dict, get_events_pool, get_intel_pool, require_auth, service_label

router = APIRouter()


@router.get("/export/stix/{ip}", dependencies=[Depends(require_auth)])
async def export_stix(ip: str):
    from stix_export import profile_to_stix

    async with get_intel_pool().acquire() as intel_conn:
        profile = await intel_conn.fetchrow(
            """
            SELECT host(ip) AS ip, risk_score, behavior_tags, total_requests,
                   first_seen, last_seen, geo_country, metadata
            FROM attacker_profiles WHERE ip = $1::inet
            """,
            ip,
        )
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
        classifications = await intel_conn.fetch(
            "SELECT classification, confidence, created_at FROM threat_classifications WHERE ip = $1::inet ORDER BY created_at DESC LIMIT 15",
            ip,
        )
    async with get_events_pool().acquire() as events_conn:
        events = await events_conn.fetch(
            "SELECT method, endpoint, created_at FROM events WHERE ip = $1::inet ORDER BY created_at DESC LIMIT 25",
            ip,
        )
    bundle = profile_to_stix(
        ip,
        _row_to_dict(profile),
        [_row_to_dict(e) for e in events],
        [_row_to_dict(c) for c in classifications],
    )
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/stix+json",
        headers={"Content-Disposition": f'attachment; filename="stix-{ip}.json"'},
    )


@router.get("/export/events.csv", dependencies=[Depends(require_auth)])
async def export_events(limit: int = Query(1000, ge=1, le=10000)):
    async with get_events_pool().acquire() as events_conn:
        rows = await events_conn.fetch(
            """
            SELECT id, service, host(ip) AS ip, method, endpoint, user_agent, status_code, created_at
            FROM events ORDER BY created_at DESC LIMIT $1
            """,
            limit,
        )
        event_dicts = [_row_to_dict(r) for r in rows]
    async with get_intel_pool().acquire() as intel_conn:
        event_dicts = await _attach_classifications(intel_conn, event_dicts)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "service", "ip", "method", "endpoint", "user_agent", "status_code",
        "classifications", "mitre_techniques", "created_at",
    ])
    for r in event_dicts:
        clf_names = "|".join(c["classification"] for c in r.get("classifications", []))
        mitre_ids = "|".join(t["id"] for t in r.get("mitre_techniques", []))
        writer.writerow([
            r["id"], service_label(r["service"]), r["ip"], r["method"], r["endpoint"],
            r.get("user_agent"), r["status_code"], clf_names, mitre_ids, r["created_at"],
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


@router.get("/export/profiles.csv", dependencies=[Depends(require_auth)])
async def export_profiles(limit: int = Query(1000, ge=1, le=10000)):
    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT host(ip) AS ip, risk_score, behavior_tags, total_requests,
                   geo_country, geo_city, geo_latitude, geo_longitude, geo_asn, geo_isp,
                   first_seen, last_seen
            FROM attacker_profiles ORDER BY risk_score DESC LIMIT $1
            """,
            limit,
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "risk_score", "behavior_tags", "total_requests",
                     "geo_country", "geo_city", "geo_latitude", "geo_longitude",
                     "geo_asn", "geo_isp", "first_seen", "last_seen"])
    for r in rows:
        writer.writerow([
            r["ip"], r["risk_score"], "|".join(r["behavior_tags"] or []),
            r["total_requests"], r["geo_country"], r["geo_city"],
            r["geo_latitude"], r["geo_longitude"], r["geo_asn"], r["geo_isp"],
            r["first_seen"].isoformat(), r["last_seen"].isoformat(),
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=profiles.csv"},
    )


@router.get("/export/blocklist.txt", dependencies=[Depends(require_auth)])
async def export_blocklist(min_risk: int = Query(40, ge=0, le=100)):
    async with get_intel_pool().acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT host(ip) AS ip, risk_score FROM attacker_profiles
            WHERE risk_score >= $1 ORDER BY risk_score DESC
            """,
            min_risk,
        )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = [
        "# Threat intelligence firewall blocklist",
        f"# Threshold: risk_score >= {min_risk}",
        f"# Generated: {generated}",
        f"# Matching IPs: {len(rows)}",
    ]
    if not rows:
        header.append("#")
        header.append("# No profiles met this threshold.")
        header.append("# Light traffic often scores below 40 — try min_risk=20 or run more attacks.")
        header.append("#")
    body = [r["ip"] for r in rows]
    content = "\n".join(header + body) + "\n"
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="blocklist_risk{min_risk}.txt"'},
    )


@router.get("/export/blocklist/{ip}", dependencies=[Depends(require_auth)])
async def export_blocklist_single(ip: str):
    """Single-IP blocklist line for edge firewall import."""
    async with get_intel_pool().acquire() as conn:
        row = await conn.fetchrow(
            "SELECT host(ip) AS ip, risk_score FROM attacker_profiles WHERE ip = $1::inet",
            ip,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    content = "\n".join([
        "# Threat intelligence single-IP blocklist",
        f"# Generated: {generated}",
        f"# Risk score: {row['risk_score']}",
        row["ip"],
        "",
    ])
    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="blocklist-{ip}.txt"'},
    )