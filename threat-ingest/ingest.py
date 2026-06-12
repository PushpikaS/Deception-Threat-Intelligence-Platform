"""Ingest honeypot events from Redis Stream into postgres-events."""

from __future__ import annotations

import json
import logging

import asyncpg
import redis.asyncio as aioredis

log = logging.getLogger(__name__)

EVENT_STREAM = "honeypot:events"
CONSUMER_GROUP = "threat-ingest"
CONSUMER_NAME = "worker-1"


async def ensure_consumer_group(redis: aioredis.Redis) -> None:
    try:
        await redis.xgroup_create(EVENT_STREAM, CONSUMER_GROUP, id="0", mkstream=True)
        log.info("Created Redis stream group %s on %s", CONSUMER_GROUP, EVENT_STREAM)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def ingest_from_stream(
    conn: asyncpg.Connection,
    redis: aioredis.Redis,
    *,
    count: int = 100,
    block_ms: int = 500,
) -> int:
    """Read pending events from the honeypot stream and persist to PostgreSQL."""
    try:
        messages = await redis.xreadgroup(
            CONSUMER_GROUP,
            CONSUMER_NAME,
            {EVENT_STREAM: ">"},
            count=count,
            block=block_ms,
        )
    except Exception as exc:
        if "NOGROUP" in str(exc):
            await ensure_consumer_group(redis)
            return 0
        raise

    if not messages:
        return 0

    ingested = 0
    for _stream, entries in messages:
        for msg_id, fields in entries:
            try:
                service = fields.get("service", "unknown")
                ip = fields.get("ip", "")
                method = fields.get("method", "GET")
                endpoint = fields.get("endpoint", "/")
                user_agent = fields.get("user_agent", "")
                status_code = int(fields.get("status_code", 200))
                payload_raw = fields.get("payload", "{}")
                if isinstance(payload_raw, str):
                    payload = json.loads(payload_raw) if payload_raw else {}
                else:
                    payload = payload_raw

                await conn.execute(
                    """
                    INSERT INTO events (service, ip, method, endpoint, payload, user_agent, status_code)
                    VALUES ($1, $2::inet, $3, $4, $5::jsonb, $6, $7)
                    """,
                    service,
                    ip,
                    method,
                    endpoint,
                    json.dumps(payload),
                    user_agent,
                    status_code,
                )
                await redis.xack(EVENT_STREAM, CONSUMER_GROUP, msg_id)
                ingested += 1
            except Exception as exc:
                log.error("Failed to ingest stream message %s: %s", msg_id, exc)

    return ingested