"""Advanced HTML insight dashboard (inventory + changes + severity)."""

from __future__ import annotations

import html
import json
import os
from typing import Any


def write_html_dashboard(
    out_dir: str,
    *,
    target: str,
    inventory: dict[str, Any],
    changes: dict[str, Any],
    inventory_scores: dict[str, Any],
    change_scores: dict[str, Any],
) -> str:
    path = os.path.join(out_dir, "dashboard.html")
    sev = html.escape(str(inventory_scores.get("max_severity", "info")))
    chg = html.escape(str(change_scores.get("max_severity", "info")))
    counts = inventory.get("counts") or {}
    hosts = inventory.get("live_hosts") or {}
    findings = (inventory_scores.get("findings") or [])[:25]
    new_ports = changes.get("new_ports") or []
    new_hosts = changes.get("new_live_hosts") or []
    baseline = bool(changes.get("baseline"))

    host_rows = []
    for name, meta in sorted(hosts.items()):
        host_rows.append(
            "<tr>"
            f"<td>{html.escape(name)}</td>"
            f"<td>{html.escape(str(meta.get('ip') or ''))}</td>"
            f"<td>{html.escape(str(meta.get('status_code') or ''))}</td>"
            f"<td>{html.escape(str(meta.get('title') or '')[:80])}</td>"
            f"<td>{html.escape(', '.join(meta.get('tech') or [])[:80])}</td>"
            "</tr>"
        )

    finding_rows = []
    for f in findings:
        finding_rows.append(
            "<tr>"
            f"<td class='sev-{html.escape(str(f.get('severity')))}'>"
            f"{html.escape(str(f.get('severity', '')).upper())}</td>"
            f"<td>{html.escape(str(f.get('score', '')))}</td>"
            f"<td>{html.escape(str(f.get('type', '')))}</td>"
            f"<td><code>{html.escape(str(f.get('asset', '')))}</code></td>"
            "</tr>"
        )

    def bullets(items: list[str]) -> str:
        if not items:
            return "<p class='muted'>None</p>"
        lis = "".join(f"<li><code>{html.escape(i)}</code></li>" for i in items[:40])
        return f"<ul>{lis}</ul>"

    payload_json = html.escape(
        json.dumps(
            {
                "target": target,
                "counts": counts,
                "overall_score": inventory_scores.get("overall_score"),
                "change_score": change_scores.get("change_score"),
            },
            indent=2,
        )
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Auto-Recon — {html.escape(target)}</title>
  <style>
    :root {{
      --bg: #0f1419; --card: #1a2332; --text: #e7ecf3; --muted: #8b9bb4;
      --accent: #3dd6c3; --line: #2a3548; --high: #ff6b6b; --med: #ffd166; --low: #90be6d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(1200px 600px at 10% -10%, #1b2a40, var(--bg));
      color: var(--text); line-height: 1.45; padding: 2rem;
    }}
    h1,h2 {{ margin: 0 0 .6rem; }}
    h1 span {{ color: var(--accent); }}
    .muted {{ color: var(--muted); }}
    .grid {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit,minmax(160px,1fr)); margin: 1.2rem 0 1.6rem; }}
    .card {{ background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 1rem 1.1rem; }}
    .stat {{ font-size: 1.6rem; font-weight: 700; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
    th, td {{ text-align: left; padding: .55rem .45rem; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    code {{ font-family: Consolas, monospace; font-size: .85rem; }}
    .sev-critical, .sev-high {{ color: var(--high); font-weight: 700; }}
    .sev-medium {{ color: var(--med); font-weight: 700; }}
    .sev-low, .sev-info {{ color: var(--low); }}
    .two {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit,minmax(280px,1fr)); }}
    footer {{ margin-top: 2rem; color: var(--muted); font-size: .85rem; }}
  </style>
</head>
<body>
  <h1>Auto-Recon <span>dashboard</span></h1>
  <p class="muted">Target <strong>{html.escape(target)}</strong> · scanned {html.escape(str(inventory.get('scanned_at') or ''))} · profile {html.escape(str(inventory.get('profile') or ''))}</p>

  <div class="grid">
    <div class="card"><div class="muted">Subdomains</div><div class="stat">{counts.get('subdomains', 0)}</div></div>
    <div class="card"><div class="muted">Live hosts</div><div class="stat">{counts.get('live_hosts', 0)}</div></div>
    <div class="card"><div class="muted">Open ports</div><div class="stat">{counts.get('open_ports', 0)}</div></div>
    <div class="card"><div class="muted">Severity</div><div class="stat sev-{sev}">{sev.upper()} ({inventory_scores.get('overall_score', 0)})</div></div>
    <div class="card"><div class="muted">Change severity</div><div class="stat sev-{chg}">{chg.upper()} ({change_scores.get('change_score', 0)})</div></div>
    <div class="card"><div class="muted">Baseline?</div><div class="stat">{"yes" if baseline else "no"}</div></div>
  </div>

  <div class="two">
    <section class="card">
      <h2>New exposure</h2>
      <h3 class="muted">Hosts</h3>
      {bullets(list(new_hosts))}
      <h3 class="muted">Ports</h3>
      {bullets(list(new_ports))}
    </section>
    <section class="card">
      <h2>Top scored findings</h2>
      <table>
        <thead><tr><th>Sev</th><th>Score</th><th>Type</th><th>Asset</th></tr></thead>
        <tbody>
          {''.join(finding_rows) if finding_rows else '<tr><td colspan="4" class="muted">None</td></tr>'}
        </tbody>
      </table>
    </section>
  </div>

  <section class="card" style="margin-top:1rem">
    <h2>Live host inventory</h2>
    <table>
      <thead><tr><th>Host</th><th>IP</th><th>Status</th><th>Title</th><th>Tech</th></tr></thead>
      <tbody>
        {''.join(host_rows) if host_rows else '<tr><td colspan="5" class="muted">None</td></tr>'}
      </tbody>
    </table>
  </section>

  <footer>
    Generated by Auto-Recon · authorized testing only<br/>
    <pre style="white-space:pre-wrap">{payload_json}</pre>
  </footer>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
