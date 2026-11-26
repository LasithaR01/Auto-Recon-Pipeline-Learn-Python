"""Export inventory assets to CSV for spreadsheets / SIEM-lite workflows."""

from __future__ import annotations

import csv
import os
from typing import Any


def write_inventory_csv(out_dir: str, inventory: dict[str, Any]) -> str:
    path = os.path.join(out_dir, "assets.csv")
    rows: list[dict[str, str]] = []

    hosts = inventory.get("live_hosts") or {}
    for host, meta in hosts.items():
        rows.append(
            {
                "type": "live_host",
                "asset": host,
                "ip": str(meta.get("ip") or ""),
                "port": "",
                "service": "",
                "status_code": str(meta.get("status_code") or ""),
                "title": str(meta.get("title") or ""),
                "tech": ",".join(meta.get("tech") or []),
            }
        )

    for ip, entries in (inventory.get("ports_by_ip") or {}).items():
        for e in entries:
            rows.append(
                {
                    "type": "open_port",
                    "asset": f"{ip}:{e.get('port')}",
                    "ip": ip,
                    "port": str(e.get("port") or ""),
                    "service": str(e.get("service") or ""),
                    "status_code": "",
                    "title": "",
                    "tech": "",
                }
            )

    fieldnames = [
        "type",
        "asset",
        "ip",
        "port",
        "service",
        "status_code",
        "title",
        "tech",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path
