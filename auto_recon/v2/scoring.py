"""Severity scoring for assets and exposure changes."""

from __future__ import annotations

from typing import Any


# Higher = more interesting / riskier for a first-pass recon view.
PORT_SEVERITY: dict[str, tuple[str, int]] = {
    "21": ("high", 70),      # FTP
    "22": ("high", 75),      # SSH
    "23": ("critical", 90),  # Telnet
    "25": ("medium", 50),    # SMTP
    "53": ("medium", 45),
    "80": ("low", 20),
    "110": ("medium", 45),
    "143": ("medium", 45),
    "443": ("low", 15),
    "445": ("critical", 95),  # SMB
    "1433": ("high", 80),     # MSSQL
    "1521": ("high", 80),     # Oracle
    "3306": ("high", 85),     # MySQL
    "3389": ("critical", 95), # RDP
    "5432": ("high", 80),     # Postgres
    "5900": ("high", 75),     # VNC
    "6379": ("high", 85),     # Redis
    "8080": ("medium", 40),
    "8443": ("medium", 40),
    "9200": ("high", 80),     # Elasticsearch
    "27017": ("high", 85),    # MongoDB
}

LEVEL_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def score_port(port: str) -> tuple[str, int]:
    return PORT_SEVERITY.get(str(port), ("info", 10))


def score_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Attach severity to each open port and compute an overall score."""
    findings: list[dict[str, Any]] = []
    total = 0
    max_level = "info"

    for ip, entries in (inventory.get("ports_by_ip") or {}).items():
        for e in entries:
            port = str(e.get("port", ""))
            level, points = score_port(port)
            total += points
            if LEVEL_RANK[level] > LEVEL_RANK[max_level]:
                max_level = level
            findings.append(
                {
                    "type": "open_port",
                    "asset": f"{ip}:{port}",
                    "ip": ip,
                    "port": port,
                    "service": e.get("service", "unknown"),
                    "severity": level,
                    "score": points,
                }
            )

    for host, meta in (inventory.get("live_hosts") or {}).items():
        # Live web assets are informational unless paired with risky ports.
        findings.append(
            {
                "type": "live_host",
                "asset": host,
                "ip": meta.get("ip"),
                "severity": "info",
                "score": 5,
                "status_code": meta.get("status_code"),
            }
        )
        total += 5

    # Soft cap so huge inventories stay readable.
    overall = min(100, total)
    return {
        "overall_score": overall,
        "max_severity": max_level,
        "findings": sorted(
            findings, key=lambda f: (-f["score"], f.get("asset", ""))
        ),
    }


def score_changes(changes: dict[str, Any]) -> dict[str, Any]:
    """
    Score *new* exposure higher than steady-state inventory.

    New ports / hosts since last scan drive alerting and the change report.
    """
    items: list[dict[str, Any]] = []
    total = 0
    max_level = "info"

    for host in changes.get("new_live_hosts") or []:
        points = 35
        level = "medium"
        total += points
        if LEVEL_RANK[level] > LEVEL_RANK[max_level]:
            max_level = level
        items.append(
            {
                "type": "new_live_host",
                "asset": host,
                "severity": level,
                "score": points,
            }
        )

    for entry in changes.get("new_ports") or []:
        # entry like "1.2.3.4:3306/tcp"
        port = entry.split(":")[-1].split("/")[0] if ":" in entry else ""
        level, base = score_port(port)
        points = min(100, base + 15)  # novelty bump
        total += points
        if LEVEL_RANK[level] > LEVEL_RANK[max_level]:
            max_level = level
        items.append(
            {
                "type": "new_port",
                "asset": entry,
                "severity": level,
                "score": points,
            }
        )

    for host in changes.get("new_subdomains") or []:
        items.append(
            {
                "type": "new_subdomain",
                "asset": host,
                "severity": "low",
                "score": 10,
            }
        )
        total += 10

    return {
        "change_score": min(100, total),
        "max_severity": max_level,
        "items": sorted(items, key=lambda i: (-i["score"], i.get("asset", ""))),
        "has_new_exposure": bool(
            changes.get("new_live_hosts") or changes.get("new_ports")
        ),
    }
