"""Threat classification rules, velocity detection, and decay-aware risk scoring."""

from __future__ import annotations

import importlib.util
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _load_trap_module():
    try:
        import shared_traps

        return shared_traps
    except ImportError:
        traps_path = Path(__file__).resolve().parent.parent / "shared" / "traps.py"
        spec = importlib.util.spec_from_file_location("shared_traps", traps_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load trap registry from {traps_path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


_trap_mod = _load_trap_module()
HOSTILE_PREFIXES = _trap_mod.hostile_prefixes()
BENIGN_AUTH_FLOW = _trap_mod.benign_auth_flow()
_TRAP_RULES = _trap_mod.trap_rules()
_ENDPOINT_RULES = _trap_mod.endpoint_rules()

SQLI_PATTERNS = [
    r"(?i)(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|';?\s*--|or\s+1\s*=\s*1)",
    r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep)",
    r"(?i)(information_schema|sys\.tables|load_file\s*\()",
]

XSS_PATTERNS = [
    r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
]

PATH_TRAVERSAL = [
    r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/",
    r"(?i)(/etc/passwd|/proc/self|win\.ini)",
]

RCE_PATTERNS = [
    r"(?i)(;?\s*(cat|ls|id|whoami|uname|pwd)\s|/bin/(ba)?sh|cmd\.exe|powershell)",
    r"(?i)(exec\s*\(|eval\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|popen\s*\()",
    r"(?i)(\$\{jndi:|Runtime\.getRuntime|ProcessBuilder|child_process)",
    r"(?i)(wget\s+http|curl\s+http|nc\s+-|/dev/tcp/)",
]

MALWARE_PATTERNS = [
    r"(?i)(mirai|emotet|coinminer|xmrig|metasploit|reverse.?shell|bind.?shell)",
    r"(?i)(base64_decode|gzinflate|str_rot13|eval\(\$_)",
    r"(?i)(\.php\?.*=|/wp-admin/|/wp-login|xmlrpc\.php|/cgi-bin/)",
    r"(?i)(pastebin\.com|raw\.githubusercontent|discord(app)?\.com/api/webhooks)",
]

SCANNER_UA = [
    r"(?i)(nmap|nikto|sqlmap|masscan|zgrab|gobuster|dirbuster|wfuzz|burp|acunetix|nessus|openvas|nuclei|httpx)",
]

BOT_UA = [
    r"(?i)(bot|crawler|spider|scrapy|curl|wget|python-requests|go-http-client|java/|headlesschrome)",
]

HONEYTOKEN_PATTERNS = [
    r"(?i)(AKIA[0-9A-Z]{16}|sk_live_[a-zA-Z0-9]{24}|acme_live_[a-zA-Z0-9]{32}|ghp_[a-zA-Z0-9]{36})",
]

@dataclass
class Classification:
    name: str
    confidence: float
    details: dict[str, Any] = field(default_factory=dict)


def _match_patterns(text: str, patterns: list[str]) -> list[str]:
    return [p for p in patterns if re.search(p, text)]


def _hostile_activity(event: dict[str, Any], endpoints: set[str]) -> bool:
    payload = event.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {}
    if payload.get("trap") or payload.get("weak_credential_attempt"):
        return True
    for ep in endpoints:
        if any(ep.startswith(p) for p in HOSTILE_PREFIXES):
            return True
    return False


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def request_velocity(recent_events: list[dict[str, Any]], ip: str, window_sec: int = 60) -> int:
    now = datetime.now(timezone.utc)
    count = 0
    for e in recent_events:
        if e.get("ip") != ip:
            continue
        ts = _parse_ts(e.get("created_at"))
        if ts and (now - ts).total_seconds() <= window_sec:
            count += 1
    return count


def _unique_login_emails(recent_events: list[dict[str, Any]], ip: str) -> set[str]:
    emails: set[str] = set()
    for e in recent_events:
        if e.get("ip") != ip or "/auth/login" not in e.get("endpoint", ""):
            continue
        payload = e.get("payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                continue
        email = payload.get("email")
        if isinstance(email, str) and email:
            emails.add(email.lower())
    return emails


def _parse_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("payload") or {}
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            payload = {"raw": payload}
    return payload


def _payload_str(event: dict[str, Any], payload: dict[str, Any]) -> str:
    endpoint = event.get("endpoint", "")
    return json.dumps(payload) + endpoint + "?" + "&".join(
        f"{k}={v}" for k, v in payload.items() if isinstance(v, (str, int, float))
    )


def classify_event_local(event: dict[str, Any]) -> list[Classification]:
    """Classifications caused by this request only — persisted per event_id."""
    results: list[Classification] = []
    endpoint = event.get("endpoint", "")
    method = event.get("method", "")
    ua = event.get("user_agent") or ""
    payload = _parse_payload(event)
    payload_str = _payload_str(event, payload)

    for name, patterns, conf in [
        ("sqli_attempt", SQLI_PATTERNS, 0.92),
        ("xss_attempt", XSS_PATTERNS, 0.88),
        ("path_traversal", PATH_TRAVERSAL, 0.85),
        ("rce_attempt", RCE_PATTERNS, 0.94),
        ("malware_indicator", MALWARE_PATTERNS, 0.9),
    ]:
        hits = _match_patterns(payload_str, patterns)
        if hits:
            results.append(Classification(name, conf, {"patterns": len(hits)}))

    if _match_patterns(payload_str, HONEYTOKEN_PATTERNS):
        results.append(Classification("honeytoken_trigger", 0.98, {"triggered": True}))

    if payload.get("waf_blocked"):
        results.append(Classification("waf_blocked", 0.88, {"blocked": True}))

    if payload.get("account_locked") or payload.get("mfa_locked"):
        results.append(Classification("brute_force", 0.9, {
            "lockout": True,
            "kind": "account" if payload.get("account_locked") else "mfa",
        }))

    if payload.get("registration_bypass") or payload.get("invite_accepted"):
        results.append(Classification("registration_bypass", 0.93, {
            "invite": bool(payload.get("invite_accepted")),
        }))

    if payload.get("ldap_pivot"):
        results.append(Classification("ldap_pivot", 0.91, {"bind": True}))

    if payload.get("oauth_client_verified"):
        results.append(Classification("oauth_misconfig", 0.86, {"client_verified": True}))

    if payload.get("mfa_backup_used"):
        results.append(Classification("mfa_bypass", 0.89, {"backup_code": True}))

    trap = payload.get("trap")
    if isinstance(trap, str) and trap:
        if trap in _TRAP_RULES:
            name, conf = _TRAP_RULES[trap]
            results.append(Classification(name, conf, {"trap": trap}))
    elif endpoint in _ENDPOINT_RULES:
        name, conf = _ENDPOINT_RULES[endpoint]
        results.append(Classification(name, conf, {"endpoint": endpoint}))

    scanner_hits = _match_patterns(ua, SCANNER_UA)
    if scanner_hits:
        results.append(Classification("scanner_tool", 0.95, {"user_agent": ua[:120]}))

    bot_hits = _match_patterns(ua, BOT_UA)
    if bot_hits and not scanner_hits:
        results.append(Classification("automated_bot", 0.75, {"user_agent": ua[:120]}))

    if payload.get("weak_credential_attempt"):
        results.append(Classification("brute_force", 0.82, {
            "weak_credential": True,
            "match": payload.get("weak_cred_match", "unknown"),
        }))

    if method == "POST" and "/auth/ldap" in endpoint:
        results.append(Classification("brute_force", 0.78, {"ldap_bind": True, "scope": "event"}))

    if not results and endpoint not in BENIGN_AUTH_FLOW and not endpoint.startswith("/admin"):
        results.append(Classification("reconnaissance", 0.4, {"scope": "event"}))

    return results


def classify_profile_context(
    event: dict[str, Any], recent_events: list[dict[str, Any]]
) -> list[Classification]:
    """IP/session-level labels — stored on attacker profile metadata only."""
    results: list[Classification] = []
    ip = event.get("ip", "")
    endpoint = event.get("endpoint", "")
    method = event.get("method", "")
    payload = _parse_payload(event)

    if method == "POST" and "/auth/login" in endpoint:
        login_attempts = sum(
            1 for e in recent_events
            if e.get("ip") == ip and "/auth/login" in e.get("endpoint", "")
        )
        if login_attempts >= 3:
            results.append(Classification(
                "brute_force",
                min(0.99, 0.6 + login_attempts * 0.05),
                {"attempts": login_attempts + 1, "scope": "session"},
            ))

        emails = _unique_login_emails(recent_events, ip)
        evt_email = payload.get("email")
        if isinstance(evt_email, str):
            emails.add(evt_email.lower())
        if len(emails) >= 4:
            results.append(Classification("credential_stuffing", 0.91, {
                "unique_emails": len(emails),
                "scope": "session",
            }))

    unique_endpoints = {e.get("endpoint") for e in recent_events if e.get("ip") == ip}
    unique_endpoints.add(endpoint)
    if len(unique_endpoints) >= 8:
        results.append(Classification("port_scanner", 0.8, {
            "endpoints": len(unique_endpoints),
            "scope": "session",
        }))

    endpoints_for_ip = {e.get("endpoint") for e in recent_events if e.get("ip") == ip}
    endpoints_for_ip.add(endpoint)
    normal_session = endpoints_for_ip.issubset(BENIGN_AUTH_FLOW)
    hostile = _hostile_activity(event, endpoints_for_ip)

    services = {e.get("service") for e in recent_events if e.get("ip") == ip}
    services.add(event.get("service"))
    if hostile and len(services) >= 2 and not normal_session:
        results.append(Classification("cross_service_probe", 0.7, {
            "services": sorted(services),
            "scope": "session",
        }))
    elif len(services) >= 3 and not normal_session:
        results.append(Classification("cross_service_probe", 0.75, {
            "services": sorted(services),
            "scope": "session",
        }))

    velocity = request_velocity(recent_events, ip, 60)
    if velocity >= 15:
        results.append(Classification("anomalous_velocity", 0.87, {
            "requests_per_minute": velocity + 1,
            "scope": "session",
        }))

    hour = datetime.now(timezone.utc).hour
    if hour < 5 or hour > 22:
        if method in ("POST", "PUT", "DELETE") or "admin" in endpoint:
            results.append(Classification("anomalous_timing", 0.65, {
                "utc_hour": hour,
                "scope": "session",
            }))

    if normal_session and not hostile:
        results.append(Classification("benign_session", 0.15, {"flow": "auth_admin", "scope": "session"}))

    return results


WEIGHTS = {
    "sqli_attempt": 25,
    "xss_attempt": 20,
    "path_traversal": 22,
    "rce_attempt": 35,
    "malware_indicator": 32,
    "honeytoken_trigger": 40,
    "scanner_tool": 30,
    "brute_force": 28,
    "credential_stuffing": 30,
    "port_scanner": 18,
    "cross_service_probe": 15,
    "automated_bot": 10,
    "anomalous_velocity": 22,
    "anomalous_timing": 12,
    "reconnaissance": 5,
    "benign_session": 0,
    "env_leak": 38,
    "config_leak": 36,
    "git_exposure": 30,
    "backup_leak": 34,
    "waf_blocked": 18,
    "registration_bypass": 32,
    "ldap_pivot": 30,
    "oauth_misconfig": 26,
    "mfa_bypass": 28,
}


def compute_risk_score(
    classifications: list[Classification],
    total_requests: int,
    *,
    last_seen: datetime | None = None,
    velocity: int = 0,
    previous_score: int = 0,
) -> int:
    score = sum(WEIGHTS.get(c.name, 5) * c.confidence for c in classifications)
    score += min(total_requests * 0.5, 20)
    score += min(velocity * 1.5, 15)

    if last_seen:
        now = datetime.now(timezone.utc)
        ts = last_seen if last_seen.tzinfo else last_seen.replace(tzinfo=timezone.utc)
        hours_idle = max(0, (now - ts).total_seconds() / 3600)
        score = max(score - min(hours_idle * 2.5, 35), 0)

    blended = int(score * 0.7 + previous_score * 0.3) if previous_score else int(score)
    return min(max(blended, 0), 100)


def behavior_tags(classifications: list[Classification]) -> list[str]:
    return sorted({c.name for c in classifications})