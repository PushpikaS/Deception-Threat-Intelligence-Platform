"""Server-side dashboard sessions stored in Redis with HttpOnly cookies."""

from __future__ import annotations

import secrets
import time
from typing import Any

import redis.asyncio as aioredis
from fastapi import Response

from app.config import (
    COOKIE_DOMAIN,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    DASHBOARD_SESSION_COOKIE,
    SESSION_TTL,
)

_redis: aioredis.Redis | None = None


def bind_redis(client: aioredis.Redis | None) -> None:
    global _redis
    _redis = client


def _session_key(token: str) -> str:
    return f"dashboard:session:{token}"


def _cookie_kwargs() -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "httponly": True,
        "secure": COOKIE_SECURE,
        "samesite": COOKIE_SAMESITE,
        "path": "/",
        "max_age": SESSION_TTL,
    }
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    return kwargs


async def create_session(username: str) -> str:
    if _redis is None:
        raise RuntimeError("redis unavailable")
    token = secrets.token_urlsafe(32)
    key = _session_key(token)
    now = int(time.time())
    await _redis.hset(
        key,
        mapping={
            "username": username,
            "created": str(now),
            "last_seen": str(now),
        },
    )
    await _redis.expire(key, SESSION_TTL)
    return token


async def validate_session(token: str | None) -> dict[str, Any] | None:
    if not token or _redis is None:
        return None
    key = _session_key(token)
    data = await _redis.hgetall(key)
    if not data:
        return None
    await _redis.hset(key, "last_seen", str(int(time.time())))
    await _redis.expire(key, SESSION_TTL)
    return data


async def invalidate_session(token: str | None) -> None:
    if not token or _redis is None:
        return
    await _redis.delete(_session_key(token))


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(DASHBOARD_SESSION_COOKIE, token, **_cookie_kwargs())


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        DASHBOARD_SESSION_COOKIE,
        path="/",
        domain=COOKIE_DOMAIN or None,
    )