"""Multi-tenant registry (local JSON — lean multi-tenant scaffold)."""

from __future__ import annotations

import json
import os
from typing import Any


DEFAULT_TENANTS_PATH = os.path.join("recon_output", "_platform", "tenants.json")


def _ensure(path: str) -> dict[str, Any]:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        data = {"tenants": {}}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def upsert_tenant(
    tenant_id: str,
    *,
    name: str | None = None,
    domains: list[str] | None = None,
    owner: str | None = None,
    path: str = DEFAULT_TENANTS_PATH,
) -> dict[str, Any]:
    data = _ensure(path)
    tenants = data.setdefault("tenants", {})
    row = tenants.get(tenant_id) or {
        "id": tenant_id,
        "name": name or tenant_id,
        "domains": [],
        "owner": owner or "unassigned",
    }
    if name:
        row["name"] = name
    if owner:
        row["owner"] = owner
    if domains:
        merged = sorted(set(row.get("domains") or []) | {d.lower() for d in domains})
        row["domains"] = merged
    tenants[tenant_id] = row
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return row


def get_tenant(tenant_id: str, path: str = DEFAULT_TENANTS_PATH) -> dict[str, Any] | None:
    data = _ensure(path)
    return (data.get("tenants") or {}).get(tenant_id)
