"""Asset inventory: normalize scan results into a comparable asset store."""

from __future__ import annotations

import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def build_inventory(
    *,
    target: str,
    subdomains: list[str],
    live_hosts: list[dict[str, Any]],
    nmap_findings: dict[str, list[dict[str, str]]],
    profile: str,
) -> dict[str, Any]:
    """
    Flatten pipeline output into a stable asset inventory.

    Assets are keyed so later diffs can say what appeared / disappeared.
    """
    hosts: dict[str, Any] = {}
    for h in live_hosts:
        name = (h.get("host") or "").lower().strip()
        if not name:
            continue
        hosts[name] = {
            "url": h.get("url"),
            "ip": h.get("ip"),
            "status_code": h.get("status_code"),
            "title": h.get("title"),
            "tech": h.get("tech") or [],
            "webserver": h.get("webserver"),
        }

    ports: dict[str, list[dict[str, str]]] = {}
    for ip, entries in (nmap_findings or {}).items():
        ports[ip] = sorted(
            entries,
            key=lambda e: int(e["port"]) if str(e.get("port", "")).isdigit() else 0,
        )

    port_index: list[str] = []
    for ip, entries in ports.items():
        for e in entries:
            port_index.append(f"{ip}:{e.get('port')}/{e.get('protocol', 'tcp')}")

    return {
        "target": target,
        "scanned_at": _utc_now(),
        "profile": profile,
        "subdomains": sorted(set(s.lower() for s in subdomains)),
        "live_hosts": hosts,
        "ports_by_ip": ports,
        "port_index": sorted(port_index),
        "counts": {
            "subdomains": len(set(subdomains)),
            "live_hosts": len(hosts),
            "open_ports": len(port_index),
            "unique_ips": len(ports),
        },
    }


def inventory_path(out_dir: str) -> str:
    return os.path.join(out_dir, "inventory.json")


def history_dir(out_dir: str) -> str:
    return os.path.join(out_dir, "history")


def load_inventory(path: str) -> dict[str, Any] | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_inventory(out_dir: str, inventory: dict[str, Any]) -> str:
    """
    Persist current inventory and archive the previous one under history/.
    """
    path = inventory_path(out_dir)
    hist = history_dir(out_dir)
    os.makedirs(hist, exist_ok=True)

    if os.path.exists(path):
        prev = load_inventory(path)
        stamp = _stamp()
        if prev and prev.get("scanned_at"):
            raw = str(prev["scanned_at"]).replace(":", "").replace("-", "")
            stamp = raw.replace("T", "-").replace("Z", "")
        archive = os.path.join(hist, f"inventory-{stamp}.json")
        shutil.copy2(path, archive)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2, ensure_ascii=False)
    return path


def load_previous_inventory(out_dir: str) -> dict[str, Any] | None:
    """Return the on-disk inventory from the last run (before overwrite)."""
    return load_inventory(inventory_path(out_dir))
