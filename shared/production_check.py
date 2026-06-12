"""Shared production secret validation for Python services."""

from __future__ import annotations

import logging
import os
import sys

log = logging.getLogger(__name__)

_INSECURE = {
    "DASHBOARD_AUTH_PASS": {"changeme_local_only"},
    "POSTGRES_PASSWORD": {"honeypot_secret"},
    "REDIS_PASSWORD": {"changeme_redis_local"},
}


def assert_production_safe() -> None:
    if os.getenv("STRICT_PRODUCTION", "").lower() not in ("1", "true", "yes"):
        return

    problems: list[str] = []
    dash_pass = os.getenv("DASHBOARD_AUTH_PASS", "changeme_local_only")
    if dash_pass in _INSECURE["DASHBOARD_AUTH_PASS"]:
        problems.append("DASHBOARD_AUTH_PASS is still the development default")
    if os.getenv("POSTGRES_PASSWORD", "honeypot_secret") in _INSECURE["POSTGRES_PASSWORD"]:
        problems.append("POSTGRES_PASSWORD is still the development default")
    if os.getenv("REDIS_PASSWORD", "changeme_redis_local") in _INSECURE["REDIS_PASSWORD"]:
        problems.append("REDIS_PASSWORD is still the development default")

    require_auth = os.getenv("REQUIRE_DASHBOARD_AUTH", "true").lower() in ("1", "true", "yes")
    if require_auth and len(dash_pass) < 16:
        problems.append("DASHBOARD_AUTH_PASS must be at least 16 characters in production")

    if problems:
        for item in problems:
            log.error("STRICT_PRODUCTION: %s", item)
        sys.exit(1)