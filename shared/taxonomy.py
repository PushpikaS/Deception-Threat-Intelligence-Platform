"""Canonical threat taxonomy — single source for engine, API, and dashboard."""

from __future__ import annotations

# Session/IP-level labels — stored on profile metadata, not on individual events.
PROFILE_CONTEXT_CLASSIFICATIONS: frozenset[str] = frozenset({
    "port_scanner",
    "cross_service_probe",
    "credential_stuffing",
    "anomalous_velocity",
    "anomalous_timing",
    "benign_session",
})

# Lower tier = more specific; wins as primary threat on an event row in the UI.
THREAT_PRIORITY: dict[str, int] = {
    "sqli_attempt": 1,
    "xss_attempt": 1,
    "path_traversal": 1,
    "rce_attempt": 1,
    "malware_indicator": 1,
    "honeytoken_trigger": 1,
    "env_leak": 1,
    "config_leak": 1,
    "git_exposure": 1,
    "backup_leak": 1,
    "mfa_bypass": 1,
    "ldap_pivot": 1,
    "oauth_misconfig": 1,
    "registration_bypass": 1,
    "waf_blocked": 1,
    "brute_force": 2,
    "credential_stuffing": 2,
    "scanner_tool": 3,
    "anomalous_velocity": 4,
    "anomalous_timing": 4,
    "port_scanner": 4,
    "cross_service_probe": 4,
    "automated_bot": 4,
    "reconnaissance": 4,
    "benign_session": 5,
}


def get_taxonomy() -> dict:
    return {
        "profile_context_classifications": sorted(PROFILE_CONTEXT_CLASSIFICATIONS),
        "threat_priority": THREAT_PRIORITY,
    }