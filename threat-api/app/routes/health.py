"""Health and platform status routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.deps import get_events_pool, get_intel_pool, get_redis, require_auth

router = APIRouter()


@router.get("/health")
async def health():
    status = {"status": "healthy", "service": "threat-api", "checks": {}}
    try:
        async with get_events_pool().acquire() as conn:
            await conn.fetchval("SELECT 1")
        status["checks"]["postgres_events"] = "ok"
    except Exception:
        status["checks"]["postgres_events"] = "error"
        status["status"] = "degraded"
    try:
        async with get_intel_pool().acquire() as conn:
            await conn.fetchval("SELECT 1")
        status["checks"]["postgres_intel"] = "ok"
    except Exception:
        status["checks"]["postgres_intel"] = "error"
        status["status"] = "degraded"
    try:
        await get_redis().ping()
        status["checks"]["redis_platform"] = "ok"
    except Exception:
        status["checks"]["redis_platform"] = "error"
        status["status"] = "degraded"
    return status


@router.get("/health/platform", dependencies=[Depends(require_auth)])
async def platform_health():
    async with get_events_pool().acquire() as events_conn:
        max_event = await events_conn.fetchval("SELECT COALESCE(MAX(id), 0) FROM events")
    async with get_intel_pool().acquire() as intel_conn:
        row = await intel_conn.fetchrow(
            "SELECT value, updated_at FROM engine_state WHERE key = 'last_processed_event_id'"
        )
        last_processed = int(row["value"]) if row else 0
        profiles = await intel_conn.fetchval("SELECT COUNT(*) FROM attacker_profiles")
    lag = max_event - last_processed
    engine_status = "ok" if lag <= 50 else "degraded" if lag <= 500 else "stale"
    return {
        "status": engine_status,
        "events_total": max_event,
        "engine_last_processed": last_processed,
        "engine_lag": lag,
        "engine_updated_at": row["updated_at"].isoformat() if row and row["updated_at"] else None,
        "profiles_total": profiles,
    }