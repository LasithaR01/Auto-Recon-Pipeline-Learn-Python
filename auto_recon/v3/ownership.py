"""Ownership mapping for assets (who owns what — lean RACI-lite)."""

from __future__ import annotations

import json
import os
from typing import Any


def ownership_path(out_dir: str) -> str:
    return os.path.join(out_dir, "ownership.json")


def load_ownership(out_dir: str) -> dict[str, Any]:
    path = ownership_path(out_dir)
    if not os.path.exists(path):
        return {"assets": {}}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def map_ownership(
    out_dir: str,
    *,
    target: str,
    tenant_owner: str | None,
    inventory: dict[str, Any] | None,
    default_owner: str = "unassigned",
) -> dict[str, Any]:
    """
    Ensure every live host / open port has an owner entry.
    Existing manual assignments are preserved.
    """
    data = load_ownership(out_dir)
    assets = data.setdefault("assets", {})
    owner = tenant_owner or default_owner

    def ensure(key: str, kind: str, label: str) -> None:
        if key not in assets:
            assets[key] = {
                "type": kind,
                "label": label,
                "owner": owner,
                "team": "security-eng",
                "criticality": "medium",
            }

    ensure(f"domain:{target}", "domain", target)
    for host in ((inventory or {}).get("live_hosts") or {}):
        ensure(f"host:{host}", "host", host)
    for ip, entries in ((inventory or {}).get("ports_by_ip") or {}).items():
        for e in entries:
            label = f"{ip}:{e.get('port')}"
            ensure(f"port:{label}", "port", label)

    data["target"] = target
    data["default_owner"] = owner
    path = ownership_path(out_dir)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    data["path"] = path
    return data
