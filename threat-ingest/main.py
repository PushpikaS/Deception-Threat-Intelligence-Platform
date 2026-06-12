"""Event ingest microservice — Redis stream to postgres-events."""

from __future__ import annotations

import asyncio
import logging
import os
import signal

import asyncpg
import redis.asyncio as aioredis

from ingest import ensure_consumer_group, ingest_from_stream
from shared_production_check import assert_production_safe

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","svc":"threat-ingest","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger(__name__)

EVENTS_DATABASE_URL = os.getenv(
    "EVENTS_DATABASE_URL",
    "postgresql://honeypot:honeypot_secret@localhost:5432/honeypot_events",
)
REDIS_EVENTS_URL = os.getenv("REDIS_EVENTS_URL", "redis://localhost:6379/0")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "100"))
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1"))

running = True


def _stop(*_) -> None:
    global running
    running = False


async def main() -> None:
    assert_production_safe()
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    pool = await asyncpg.create_pool(EVENTS_DATABASE_URL, min_size=2, max_size=6)
    redis = aioredis.from_url(REDIS_EVENTS_URL, decode_responses=True)
    await ensure_consumer_group(redis)

    log.info("Threat ingest started batch=%d poll=%ss", BATCH_SIZE, POLL_INTERVAL)

    try:
        while running:
            async with pool.acquire() as conn:
                ingested = await ingest_from_stream(conn, redis, count=BATCH_SIZE, block_ms=500)
                if ingested:
                    log.info("Ingested %d events from stream", ingested)
            await asyncio.sleep(POLL_INTERVAL)
    finally:
        await redis.aclose()
        await pool.close()
        log.info("Threat ingest stopped")


if __name__ == "__main__":
    asyncio.run(main())