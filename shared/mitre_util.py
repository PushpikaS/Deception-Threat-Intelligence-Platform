"""Shared MITRE technique de-duplication for API and engine."""

from __future__ import annotations


def unique_mitre(classifications: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for clf in classifications:
        for tech in clf.get("mitre") or []:
            tid = tech.get("id")
            if tid and tid not in seen:
                seen.add(tid)
                result.append(tech)
    return result