"""Disk cache for expensive passive enum results (huge re-run speedup)."""

from __future__ import annotations

import json
import os
import time
from typing import Any


def cache_path(out_dir: str) -> str:
    return os.path.join(out_dir, ".cache", "subdomains.json")


def load_subdomain_cache(
    out_dir: str,
    *,
    target: str,
    ttl_seconds: int,
) -> list[str] | None:
    """
    Return cached subdomains if fresh and for the same target.

    ttl_seconds <= 0 disables reads.
    """
    if ttl_seconds <= 0:
        return None
    path = cache_path(out_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    if data.get("target") != target:
        return None
    saved = float(data.get("saved_at", 0))
    if time.time() - saved > ttl_seconds:
        return None
    subs = data.get("subdomains")
    if not isinstance(subs, list) or not subs:
        return None
    return [str(s).lower() for s in subs if str(s).strip()]


def save_subdomain_cache(out_dir: str, *, target: str, subdomains: list[str]) -> str:
    path = cache_path(out_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "target": target,
        "saved_at": time.time(),
        "count": len(subdomains),
        "subdomains": subdomains,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path
