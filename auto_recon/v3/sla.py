"""SLA tracking for exposure / uptime (lean risk-posture SLAs)."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Only SLAs that change risk posture (lean principle).
DEFAULT_SLAS = [
    {
        "id": "uptime_availability",
        "title": "Public site availability",
        "target": "99.5% checks up",
        "control": "uptime_monitoring",
    },
    {
        "id": "close_risky_ports",
        "title": "Close/firewall risky internet ports",
        "target": "0 high-risk ports on internet edge",
        "control": "port_exposure",
    },
    {
        "id": "fix_broken_pages",
        "title": "Fix broken customer-facing pages",
        "target": "0 broken links on sampled crawl",
        "control": "page_health",
    },
    {
        "id": "harden_headers",
        "title": "Deploy baseline security headers",
        "target": "HSTS + CSP + XFO present",
        "control": "security_headers",
    },
]


def evaluate_slas(
    *,
    monitor: dict[str, Any] | None,
    inventory_scores: dict[str, Any] | None = None,
) -> dict[str, Any]:
    up = (monitor or {}).get("uptime") or {}
    health = (monitor or {}).get("health") or {}
    posture = (monitor or {}).get("posture") or {}
    risk = (monitor or {}).get("exposure_risk") or {}

    results = []
    for sla in DEFAULT_SLAS:
        status = "pass"
        detail = "ok"
        sid = sla["id"]
        if sid == "uptime_availability":
            if not up.get("overall_up", True):
                status, detail = "fail", "Site failed latest uptime check"
            else:
                detail = f"{up.get('up_count', 0)}/{up.get('checked', 0)} endpoints up"
        elif sid == "close_risky_ports":
            risky = posture.get("risky_ports") or []
            if risky:
                status, detail = "fail", f"{len(risky)} risky port exposure(s)"
            else:
                detail = "No high-risk edge ports observed"
        elif sid == "fix_broken_pages":
            broken = int(health.get("broken_count") or 0)
            if broken:
                status, detail = "fail", f"{broken} broken page(s)"
            else:
                detail = "No broken pages in sample"
        elif sid == "harden_headers":
            missing = (posture.get("security_headers") or {}).get("missing") or []
            critical = [h for h in missing if h in (
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
            )]
            if critical:
                status, detail = "fail", f"Missing: {', '.join(critical)}"
            elif missing:
                status, detail = "warn", f"Missing optional: {', '.join(missing)}"
            else:
                detail = "Baseline headers present"

        results.append({**sla, "status": status, "detail": detail})

    failing = sum(1 for r in results if r["status"] == "fail")
    return {
        "evaluated_at": _utc_now(),
        "exposure_risk_level": risk.get("level"),
        "failing": failing,
        "passing": sum(1 for r in results if r["status"] == "pass"),
        "items": results,
        "inventory_severity": (inventory_scores or {}).get("max_severity"),
    }


def save_sla(out_dir: str, report: dict[str, Any]) -> str:
    path = os.path.join(out_dir, "sla.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path
