"""Minimal STIX 2.1 bundle export for a single attacker profile."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def _stix_id(prefix: str) -> str:
    return f"{prefix}--{uuid4()}"


def profile_to_stix(ip: str, profile: dict[str, Any], events: list[dict], classifications: list[dict]) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    identity_id = _stix_id("identity")
    indicator_id = _stix_id("indicator")
    observed_id = _stix_id("observed-data")

    tags = profile.get("behavior_tags") or []
    meta = profile.get("metadata") or {}
    mitre = meta.get("mitre_techniques") or []

    pattern_parts = [f"[ipv4-addr:value = '{ip}']"]
    for t in mitre[:5]:
        pattern_parts.append(f"[attack-pattern:name = '{t.get('name', '')}']")

    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "AcmeCorp Threat Intelligence",
            "identity_class": "system",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"Threat profile {ip}",
            "description": f"Risk {profile.get('risk_score', 0)} — behaviors: {', '.join(tags)}",
            "pattern": " AND ".join(pattern_parts[:3]),
            "pattern_type": "stix",
            "valid_from": profile.get("first_seen") or now,
            "labels": tags,
            "confidence": min(100, int(profile.get("risk_score", 0))) / 100,
        },
        {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": profile.get("first_seen") or now,
            "last_observed": profile.get("last_seen") or now,
            "number_observed": profile.get("total_requests", 0),
            "objects": {
                str(i): {
                    "type": "network-traffic",
                    "protocols": ["http"],
                    "extensions": {
                        "http-request-ext": {
                            "request_method": e.get("method"),
                            "request_value": e.get("endpoint"),
                        }
                    },
                }
                for i, e in enumerate(events[:10])
            },
        },
    ]

    for c in classifications[:10]:
        objects.append({
            "type": "note",
            "spec_version": "2.1",
            "id": _stix_id("note"),
            "created": c.get("created_at") or now,
            "modified": c.get("created_at") or now,
            "content": f"{c.get('classification')} ({float(c.get('confidence', 0)):.0%})",
            "object_refs": [indicator_id],
        })

    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "objects": objects,
    }