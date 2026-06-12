"""Auth config, taxonomy, and MITRE metadata routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.config import REQUIRE_DASHBOARD_AUTH
from app.deps import require_auth

router = APIRouter()


@router.get("/auth/config")
async def auth_config():
    """Public — tells the dashboard whether credentials are required."""
    return {"required": REQUIRE_DASHBOARD_AUTH}


@router.get("/taxonomy", dependencies=[Depends(require_auth)])
async def taxonomy():
    from shared_taxonomy import get_taxonomy

    return get_taxonomy()


@router.get("/mitre/map", dependencies=[Depends(require_auth)])
async def mitre_map():
    from shared_mitre import MITRE_MAP

    return MITRE_MAP