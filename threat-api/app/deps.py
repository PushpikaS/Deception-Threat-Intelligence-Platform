"""Shared dependencies, helpers, and auth for route handlers."""

from __future__ import annotations

import json
import secrets
from datetime import datetime
from typing import Any

import asyncpg
import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from app.config import (
    CACHE_TTL,
    DASHBOARD_AUTH_PASS,
    DASHBOARD_AUTH_USER,
    DASHBOARD_SESSION_COOKIE,
    REQUIRE_DASHBOARD_AUTH,
)
from app.session import validate_session
from shared_mitre_util import unique_mitre

security = HTTPBasic(auto_error=False)

SERVICE_LABELS = {
    "honeypot-web": "Web",
    "honeypot-api": "API",
    "honeypot-auth": "Identity",
}


def service_label(service: str | None) -> str:
    if not service:
        return ""
    return SERVICE_LABELS.get(service, service)

events_pool: asyncpg.Pool | None = None
intel_pool: asyncpg.Pool | None = None
redis_client: aioredis.Redis | None = None


def get_events_pool() -> asyncpg.Pool:
    if events_pool is None:
        raise HTTPException(status_code=503, detail="Events database pool not ready")
    return events_pool


def get_intel_pool() -> asyncpg.Pool:
    if intel_pool is None:
        raise HTTPException(status_code=503, detail="Intel database pool not ready")
    return intel_pool


def get_redis() -> aioredis.Redis:
    if redis_client is None:
        raise HTTPException(status_code=503, detail="Redis not ready")
    return redis_client

_JSONB_FIELDS = frozenset({"metadata", "payload", "details"})


async def require_auth(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(security),
) -> None:
    if not REQUIRE_DASHBOARD_AUTH:
        return

    token = request.cookies.get(DASHBOARD_SESSION_COOKIE)
    if await validate_session(token):
        return

    if credentials:
        user_ok = secrets.compare_digest(credentials.username, DASHBOARD_AUTH_USER)
        pass_ok = secrets.compare_digest(credentials.password, DASHBOARD_AUTH_PASS)
        if user_ok and pass_ok:
            return

    raise HTTPException(status_code=401, detail="Authentication required")


def _row_to_dict(row: asyncpg.Record) -> dict:
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, datetime):
            d[k] = v.isoformat()
        elif k in _JSONB_FIELDS and isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except json.JSONDecodeError:
                pass
    return d


async def _attach_classifications(conn: asyncpg.Connection, events: list[dict]) -> list[dict]:
    if not events:
        return events
    event_ids = [e["id"] for e in events]
    rows = await conn.fetch(
        """
        SELECT event_id, classification, confidence, details
        FROM threat_classifications
        WHERE event_id = ANY($1::bigint[])
        ORDER BY confidence DESC
        """,
        event_ids,
    )
    by_event: dict[int, list[dict]] = {}
    for row in rows:
        d = _row_to_dict(row)
        event_id = d.pop("event_id")
        details = d.get("details") or {}
        d["mitre"] = details.get("mitre") or []
        by_event.setdefault(event_id, []).append(d)
    for event in events:
        clfs = by_event.get(event["id"], [])
        event["classifications"] = clfs
        event["mitre_techniques"] = unique_mitre(clfs)
    return events


async def _cached(key: str, fetcher) -> Any:
    cached = await redis_client.get(key)
    if cached:
        return json.loads(cached)
    data = await fetcher()
    await redis_client.setex(key, CACHE_TTL, json.dumps(data, default=str))
    return data


def _geo_source_from_row(row: asyncpg.Record) -> str:
    meta = row.get("metadata")
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except json.JSONDecodeError:
            meta = {}
    if isinstance(meta, dict):
        return meta.get("geo_source") or "unknown"
    return "unknown"