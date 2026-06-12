"""Load canonical trap classification rules from shared/trap_registry.json."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path


def _registry_path() -> Path:
    if env_path := os.getenv("TRAP_REGISTRY_PATH"):
        return Path(env_path)
    here = Path(__file__).resolve().parent
    for candidate in (
        here / "trap_registry.json",
        here.parent / "shared" / "trap_registry.json",
    ):
        if candidate.is_file():
            return candidate
    return here / "trap_registry.json"


@lru_cache(maxsize=1)
def load_registry() -> dict:
    with _registry_path().open(encoding="utf-8") as fh:
        return json.load(fh)


def hostile_prefixes() -> tuple[str, ...]:
    return tuple(load_registry()["hostile_prefixes"])


def benign_auth_flow() -> frozenset[str]:
    return frozenset(load_registry()["benign_auth_flow"])


def trap_rules() -> dict[str, tuple[str, float]]:
    return {
        name: (rule["classification"], rule["confidence"])
        for name, rule in load_registry()["trap_rules"].items()
    }


def endpoint_rules() -> dict[str, tuple[str, float]]:
    return {
        path: (rule["classification"], rule["confidence"])
        for path, rule in load_registry()["endpoint_rules"].items()
    }


def sensitive_traps() -> frozenset[str]:
    return frozenset(load_registry()["sensitive_traps"])