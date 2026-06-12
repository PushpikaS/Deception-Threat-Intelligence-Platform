"""Environment configuration and logging for the threat API."""

from __future__ import annotations

import logging
import os

from shared_production_check import assert_production_safe

EVENTS_DATABASE_URL = os.getenv(
    "EVENTS_DATABASE_URL",
    "postgresql://honeypot:honeypot_secret@localhost:5432/honeypot_events",
)
INTEL_DATABASE_URL = os.getenv(
    "INTEL_DATABASE_URL",
    "postgresql://honeypot:honeypot_secret@localhost:5432/threat_intel",
)
REDIS_PLATFORM_URL = os.getenv("REDIS_PLATFORM_URL", "redis://localhost:6379/0")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:9090").split(",") if o.strip()]
CACHE_TTL = int(os.getenv("CACHE_TTL", "30"))
REQUIRE_DASHBOARD_AUTH = os.getenv("REQUIRE_DASHBOARD_AUTH", "true").lower() in ("1", "true", "yes")
DASHBOARD_AUTH_USER = os.getenv("DASHBOARD_AUTH_USER", "analyst")
DASHBOARD_AUTH_PASS = os.getenv("DASHBOARD_AUTH_PASS", "changeme_local_only")
DASHBOARD_SESSION_COOKIE = os.getenv("DASHBOARD_SESSION_COOKIE", "hp_session")
SESSION_TTL = int(os.getenv("DASHBOARD_SESSION_TTL", "28800"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax").lower()
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "").strip() or None

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","svc":"threat-api","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger(__name__)