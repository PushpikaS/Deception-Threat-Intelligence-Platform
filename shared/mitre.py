"""Canonical MITRE ATT&CK mapping — single source of truth for engine and API."""

from __future__ import annotations

MITRE_MAP: dict[str, list[dict[str, str]]] = {
    "sqli_attempt": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505", "name": "Server Software Component", "tactic": "Persistence"},
    ],
    "xss_attempt": [
        {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
        {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"},
    ],
    "path_traversal": [
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "rce_attempt": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    ],
    "malware_indicator": [
        {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "honeytoken_trigger": [
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
    "brute_force": [
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
    ],
    "credential_stuffing": [
        {"id": "T1110.004", "name": "Credential Stuffing", "tactic": "Credential Access"},
    ],
    "scanner_tool": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "port_scanner": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "cross_service_probe": [
        {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
    ],
    "automated_bot": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "anomalous_velocity": [
        {"id": "T1499", "name": "Endpoint Denial of Service", "tactic": "Impact"},
    ],
    "anomalous_timing": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    ],
    "reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "benign_session": [],
    "env_leak": [
        {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
    ],
    "config_leak": [
        {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
        {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    ],
    "git_exposure": [
        {"id": "T1211", "name": "Exploitation for Defense Evasion", "tactic": "Defense Evasion"},
    ],
    "backup_leak": [
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "waf_blocked": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
    ],
    "registration_bypass": [
        {"id": "T1078.004", "name": "Cloud Accounts", "tactic": "Defense Evasion"},
        {"id": "T1133", "name": "External Remote Services", "tactic": "Persistence"},
    ],
    "ldap_pivot": [
        {"id": "T1078.002", "name": "Domain Accounts", "tactic": "Defense Evasion"},
        {"id": "T1550", "name": "Use Alternate Authentication Material", "tactic": "Defense Evasion"},
    ],
    "oauth_misconfig": [
        {"id": "T1550.001", "name": "Application Access Token", "tactic": "Defense Evasion"},
    ],
    "mfa_bypass": [
        {"id": "T1556.006", "name": "Multi-Factor Authentication", "tactic": "Credential Access"},
    ],
}

# Classifications that must never receive a fallback technique
_NO_MITRE = frozenset({"benign_session"})


def mitre_for_classification(name: str) -> list[dict[str, str]]:
    if name in _NO_MITRE:
        return []
    if name in MITRE_MAP:
        return MITRE_MAP[name]
    return [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"}]


def mitre_for_classifications(names: list[str]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for name in names:
        for tech in mitre_for_classification(name):
            if tech["id"] not in seen:
                seen.add(tech["id"])
                result.append(tech)
    return result