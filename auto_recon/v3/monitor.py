"""Run v3 monitoring pack and write monitor.json / monitor.md."""

from __future__ import annotations

import json
import os
from typing import Any

from auto_recon.v3.health import analyze_health
from auto_recon.v3.posture import analyze_posture
from auto_recon.v3.risk_score import compute_exposure_risk
from auto_recon.v3.uptime import check_uptime, save_uptime


def run_monitor(
    out_dir: str,
    *,
    target: str,
    live_hosts: list[dict[str, Any]] | None = None,
    nmap_findings: dict[str, list[dict[str, str]]] | None = None,
    inventory_scores: dict[str, Any] | None = None,
) -> dict[str, Any]:
    uptime = check_uptime(target, live_hosts)
    save_uptime(out_dir, uptime)
    health = analyze_health(target, live_hosts)
    posture = analyze_posture(target, live_hosts, nmap_findings)
    risk = compute_exposure_risk(
        uptime=uptime,
        health=health,
        posture=posture,
        inventory_scores=inventory_scores,
    )

    report = {
        "target": target,
        "uptime": uptime,
        "health": health,
        "posture": posture,
        "exposure_risk": risk,
    }

    json_path = os.path.join(out_dir, "monitor.json")
    md_path = os.path.join(out_dir, "monitor.md")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(_render_md(report))

    report["paths"] = {"json": json_path, "md": md_path}
    return report


def _render_md(report: dict[str, Any]) -> str:
    target = report.get("target")
    up = report.get("uptime") or {}
    health = report.get("health") or {}
    posture = report.get("posture") or {}
    risk = report.get("exposure_risk") or {}
    seo = health.get("seo") or {}
    lines = [
        f"# Site monitor — `{target}`",
        "",
        f"- Uptime: **{'UP' if up.get('overall_up') else 'DOWN'}** "
        f"({up.get('up_count', 0)}/{up.get('checked', 0)})",
        f"- Broken pages: **{health.get('broken_count', 0)}** "
        f"(checked {health.get('links_checked', 0)} links)",
        f"- SEO score: **{seo.get('seo_score', 'n/a')}**",
        f"- Exposure risk: **{risk.get('level', 'info').upper()}** "
        f"({risk.get('exposure_risk_score', 0)}/100)",
        "",
        "> Defensive monitoring only. Not a full vuln scan / not proof a site can be hacked.",
        "",
        "## Exposure factors",
        "",
    ]
    factors = risk.get("factors") or []
    if not factors:
        lines.append("_None significant_")
    else:
        for fac in factors:
            lines.append(
                f"- **+{fac.get('points')}** `{fac.get('code')}` — {fac.get('detail')}"
            )
    lines += ["", "## Login / admin surfaces", ""]
    logins = posture.get("login_surfaces") or []
    if not logins:
        lines.append("_None detected_")
    else:
        for item in logins:
            lines.append(
                f"- `{item.get('url')}` ({item.get('status')}) — {item.get('signal')}"
            )
    lines += ["", "## Missing security headers", ""]
    missing = (posture.get("security_headers") or {}).get("missing") or []
    if not missing:
        lines.append("_None_")
    else:
        for h in missing:
            lines.append(f"- `{h}`")
    lines += ["", "## Broken pages", ""]
    broken = health.get("broken_pages") or []
    if not broken:
        lines.append("_None_")
    else:
        for b in broken[:30]:
            lines.append(f"- `{b.get('url')}` → {b.get('status') or b.get('error')}")
    lines.append("")
    return "\n".join(lines)
