"""Executive dashboard — lean risk posture view for leadership."""

from __future__ import annotations

import html
import json
import os
from typing import Any


def write_executive_dashboard(
    out_dir: str,
    *,
    target: str,
    tenant: dict[str, Any] | None,
    monitor: dict[str, Any] | None,
    sla: dict[str, Any] | None,
    graph: dict[str, Any] | None,
    tickets: list[dict[str, Any]] | None,
) -> str:
    path = os.path.join(out_dir, "executive.html")
    risk = (monitor or {}).get("exposure_risk") or {}
    up = (monitor or {}).get("uptime") or {}
    health = (monitor or {}).get("health") or {}
    seo = health.get("seo") or {}
    level = html.escape(str(risk.get("level", "info")))
    score = risk.get("exposure_risk_score", 0)
    tenant_name = html.escape(str((tenant or {}).get("name") or "default"))
    owner = html.escape(str((tenant or {}).get("owner") or "unassigned"))

    sla_rows = []
    for item in (sla or {}).get("items") or []:
        st = html.escape(str(item.get("status", "")))
        sla_rows.append(
            "<tr>"
            f"<td class='st-{st}'>{st.upper()}</td>"
            f"<td>{html.escape(str(item.get('title', '')))}</td>"
            f"<td>{html.escape(str(item.get('detail', '')))}</td>"
            f"<td><code>{html.escape(str(item.get('control', '')))}</code></td>"
            "</tr>"
        )

    ticket_rows = []
    for t in tickets or []:
        ticket_rows.append(
            "<tr>"
            f"<td>{html.escape(str(t.get('priority', '')))}</td>"
            f"<td>{html.escape(str(t.get('title', '')))}</td>"
            f"<td>{html.escape(str(t.get('owner', '')))}</td>"
            f"<td>{html.escape(str(t.get('detail', '')))}</td>"
            "</tr>"
        )

    factors = risk.get("factors") or []
    factor_lis = "".join(
        f"<li><strong>+{html.escape(str(f.get('points')))}</strong> "
        f"{html.escape(str(f.get('detail', '')))}</li>"
        for f in factors[:12]
    ) or "<li class='muted'>No major exposure factors</li>"

    counts = (graph or {}).get("counts") or {}
    payload = html.escape(
        json.dumps(
            {
                "target": target,
                "exposure_risk_score": score,
                "level": risk.get("level"),
                "sla_failing": (sla or {}).get("failing"),
                "open_tickets": len(tickets or []),
            },
            indent=2,
        )
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Executive Exposure — {html.escape(target)}</title>
  <style>
    :root {{
      --bg:#0b1220; --card:#152238; --text:#eef3fb; --muted:#93a4bd;
      --line:#243552; --accent:#5eead4; --fail:#fb7185; --warn:#fbbf24; --pass:#34d399;
    }}
    body {{ margin:0; font-family:"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem; }}
    h1 span {{ color:var(--accent); }}
    .muted {{ color:var(--muted); }}
    .grid {{ display:grid; gap:1rem; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); margin:1.2rem 0; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:14px; padding:1rem 1.1rem; }}
    .stat {{ font-size:1.7rem; font-weight:700; }}
    .st-fail {{ color:var(--fail); font-weight:700; }}
    .st-warn {{ color:var(--warn); font-weight:700; }}
    .st-pass {{ color:var(--pass); font-weight:700; }}
    .sev-critical,.sev-high {{ color:var(--fail); }}
    .sev-medium {{ color:var(--warn); }}
    .sev-low,.sev-info {{ color:var(--pass); }}
    table {{ width:100%; border-collapse:collapse; font-size:.92rem; }}
    th,td {{ text-align:left; padding:.55rem .4rem; border-bottom:1px solid var(--line); vertical-align:top; }}
    th {{ color:var(--muted); }}
    .two {{ display:grid; gap:1rem; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); }}
    code {{ font-family:Consolas,monospace; font-size:.85rem; }}
    footer {{ margin-top:1.5rem; color:var(--muted); font-size:.85rem; }}
  </style>
</head>
<body>
  <h1>Continuous Exposure <span>Executive</span></h1>
  <p class="muted">Tenant <strong>{tenant_name}</strong> · Owner <strong>{owner}</strong> · Target <strong>{html.escape(target)}</strong></p>
  <p class="muted">Lean principle: only controls that change risk posture.</p>

  <div class="grid">
    <div class="card"><div class="muted">Exposure risk</div><div class="stat sev-{level}">{level.upper()} ({score})</div></div>
    <div class="card"><div class="muted">Uptime</div><div class="stat">{"UP" if up.get("overall_up") else "DOWN"}</div></div>
    <div class="card"><div class="muted">Broken pages</div><div class="stat">{health.get("broken_count", 0)}</div></div>
    <div class="card"><div class="muted">SEO score</div><div class="stat">{seo.get("seo_score", "n/a")}</div></div>
    <div class="card"><div class="muted">SLA failing</div><div class="stat">{(sla or {}).get("failing", 0)}</div></div>
    <div class="card"><div class="muted">Open tickets</div><div class="stat">{len(tickets or [])}</div></div>
    <div class="card"><div class="muted">Graph hosts</div><div class="stat">{counts.get("hosts", 0)}</div></div>
    <div class="card"><div class="muted">Graph ports</div><div class="stat">{counts.get("ports", 0)}</div></div>
  </div>

  <div class="two">
    <section class="card">
      <h2>Risk factors</h2>
      <ul>{factor_lis}</ul>
    </section>
    <section class="card">
      <h2>SLA controls</h2>
      <table>
        <thead><tr><th>Status</th><th>SLA</th><th>Detail</th><th>Control</th></tr></thead>
        <tbody>{''.join(sla_rows) or '<tr><td colspan="4" class="muted">None</td></tr>'}</tbody>
      </table>
    </section>
  </div>

  <section class="card" style="margin-top:1rem">
    <h2>Tickets (failed controls only)</h2>
    <table>
      <thead><tr><th>Priority</th><th>Title</th><th>Owner</th><th>Detail</th></tr></thead>
      <tbody>{''.join(ticket_rows) or '<tr><td colspan="4" class="muted">No open risk tickets</td></tr>'}</tbody>
    </table>
  </section>

  <footer>
    Defensive monitoring · Not a full vulnerability / malware / exploit assessment<br/>
    <pre>{payload}</pre>
  </footer>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
