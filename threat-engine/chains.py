"""Attack chain narrative generation from observed events."""

from __future__ import annotations

from typing import Any

STAGE_ORDER = [
    ("reconnaissance", "Reconnaissance"),
    ("scanner_tool", "Active scanning"),
    ("port_scanner", "Endpoint enumeration"),
    ("env_leak", "Credential file hunting"),
    ("git_exposure", "Source repository exposure"),
    ("backup_leak", "Backup artifact access"),
    ("brute_force", "Credential guessing"),
    ("credential_stuffing", "Credential stuffing"),
    ("sqli_attempt", "SQL injection"),
    ("xss_attempt", "Cross-site scripting"),
    ("rce_attempt", "Remote code execution"),
    ("honeytoken_trigger", "Honeytoken access"),
    ("cross_service_probe", "Multi-service probing"),
    ("ldap_pivot", "LDAP service account pivot"),
    ("oauth_misconfig", "OAuth client abuse"),
    ("registration_bypass", "Invite code bypass"),
    ("mfa_bypass", "MFA backup code abuse"),
    ("waf_blocked", "WAF evasion attempts"),
]


def _stage_from_tags(tags: set[str]) -> str | None:
    for tag, label in STAGE_ORDER:
        if tag in tags:
            return label
    return None


def build_chain_summary(
    services: list[str],
    classifications: list[str],
    endpoints: list[str],
) -> str:
    tags = set(classifications)
    stages: list[str] = []

    stage = _stage_from_tags(tags)
    if stage:
        stages.append(stage)

    trap_hits = sum(1 for ep in endpoints if ep.startswith(("/.", "/backup", "/actuator", "/jenkins", "/jira", "/storage")))
    if trap_hits and "Credential file hunting" not in stages:
        stages.append(f"Trap access ({trap_hits} hits)")

    if "/auth/login" in endpoints or "/wp-admin" in " ".join(endpoints):
        if "brute_force" in tags or "credential_stuffing" in tags:
            stages.append("Authentication abuse")
        elif any("/admin" in ep for ep in endpoints):
            stages.append("Session pivot to admin")

    if "ldap_pivot" in tags or "/auth/ldap/bind" in endpoints:
        stages.append("Directory service pivot")

    if "oauth_misconfig" in tags or "/auth/oauth/callback" in endpoints:
        stages.append("OAuth token chain")

    if "registration_bypass" in tags or "/auth/register" in endpoints:
        stages.append("Invite registration bypass")

    if "mfa_bypass" in tags or "/auth/mfa/verify" in endpoints:
        if "MFA backup code abuse" not in stages:
            stages.append("MFA backup code abuse")

    svc = ", ".join(services)
    if len(stages) >= 2:
        return f"{' → '.join(stages[:4])} across {svc}"
    if stages:
        return f"{stages[0]} on {svc}"
    return f"Probed {len(services)} services: {svc}"