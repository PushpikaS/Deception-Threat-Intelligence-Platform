"""FastAPI threat intelligence API — REST, search, exports, caching."""

from __future__ import annotations

from contextlib import asynccontextmanager

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import deps
from app.config import (
    CORS_ORIGINS,
    EVENTS_DATABASE_URL,
    INTEL_DATABASE_URL,
    REDIS_PLATFORM_URL,
    REQUIRE_DASHBOARD_AUTH,
    assert_production_safe,
    log,
)
from app.routes import auth_routes, events, exports, health, meta, profiles, stats, ws
from app.session import bind_redis


@asynccontextmanager
async def lifespan(app: FastAPI):
    assert_production_safe()
    deps.events_pool = await asyncpg.create_pool(EVENTS_DATABASE_URL, min_size=2, max_size=8)
    deps.intel_pool = await asyncpg.create_pool(INTEL_DATABASE_URL, min_size=2, max_size=10)
    deps.redis_client = aioredis.from_url(REDIS_PLATFORM_URL, decode_responses=True)
    bind_redis(deps.redis_client)
    log.info("Threat API started auth=%s", "enabled" if REQUIRE_DASHBOARD_AUTH else "disabled")
    yield
    await deps.redis_client.aclose()
    await deps.events_pool.close()
    await deps.intel_pool.close()


app = FastAPI(title="HoneyPot+ Threat API", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(health.router)
app.include_router(stats.router)
app.include_router(profiles.router)
app.include_router(events.router)
app.include_router(exports.router)
app.include_router(meta.router)
app.include_router(ws.router)