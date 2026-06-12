"""Dashboard login, logout, and session validation."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.config import DASHBOARD_AUTH_PASS, DASHBOARD_AUTH_USER, REQUIRE_DASHBOARD_AUTH
from app.deps import require_auth
from app.session import (
    clear_session_cookie,
    create_session,
    invalidate_session,
    set_session_cookie,
    validate_session,
)

router = APIRouter()


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


@router.post("/auth/login")
async def login(body: LoginBody, response: Response):
    if not REQUIRE_DASHBOARD_AUTH:
        return {"authenticated": True, "required": False}

    user_ok = secrets.compare_digest(body.username, DASHBOARD_AUTH_USER)
    pass_ok = secrets.compare_digest(body.password, DASHBOARD_AUTH_PASS)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = await create_session(body.username)
    set_session_cookie(response, token)
    return {"authenticated": True, "required": True, "username": body.username}


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    from app.config import DASHBOARD_SESSION_COOKIE

    token = request.cookies.get(DASHBOARD_SESSION_COOKIE)
    await invalidate_session(token)
    clear_session_cookie(response)
    return {"ok": True}


@router.get("/auth/session")
async def session_status(request: Request):
    from app.config import DASHBOARD_SESSION_COOKIE

    if not REQUIRE_DASHBOARD_AUTH:
        return {"authenticated": True, "required": False}

    token = request.cookies.get(DASHBOARD_SESSION_COOKIE)
    data = await validate_session(token)
    if not data:
        return {"authenticated": False, "required": True}
    return {
        "authenticated": True,
        "required": True,
        "username": data.get("username"),
    }


@router.get("/auth/me", dependencies=[Depends(require_auth)])
async def auth_me(request: Request):
    from app.config import DASHBOARD_SESSION_COOKIE

    token = request.cookies.get(DASHBOARD_SESSION_COOKIE)
    data = await validate_session(token)
    return {"username": (data or {}).get("username") or DASHBOARD_AUTH_USER}