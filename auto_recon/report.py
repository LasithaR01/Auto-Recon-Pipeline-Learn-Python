"""Final JSON report assembly."""

from __future__ import annotations

import json
import os
from typing import Any

from auto_recon import APP_VERSION
from auto_recon.env import detect_environment


def collect_open_ports(nmap_findings: dict[str, list[dict[str, str]]]) -> list[str]:
    ports: set[str] = set()
    for entries in nmap_findings.values():
        for item in entries:
            p = item.get("port")
            if p:
                ports.add(p)
    return sorted(ports, key=lambda x: int(x) if x.isdigit() else x)


def write_report(
    target: str,
    out_dir: str,
    subdomains: list[str],
    live_hosts: list[dict[str, Any]],
    nmap_findings: dict[str, list[dict[str, str]]],
    profile: str = "balanced",
) -> str:
    """Assemble the single JSON artifact that later versions can extend."""
    # Drop bulky raw DNS arrays from the final report for cleaner/faster writes.
    slim_hosts = []
    for h in live_hosts:
        slim_hosts.append(
            {k: v for k, v in h.items() if k not in ("a", "aaaa")}
        )

    report = {
        "target": target,
        "version": APP_VERSION,
        "profile": profile,
        "environment": detect_environment(),
        "total_subdomains": len(subdomains),
        "total_live_hosts": len(live_hosts),
        "subdomains": subdomains,
        "live_hosts": slim_hosts,
        "nmap_findings": nmap_findings,
    }

    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return report_path
