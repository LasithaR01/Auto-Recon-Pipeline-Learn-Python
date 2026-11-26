"""Write change-since-last-scan artifacts (JSON + Markdown)."""

from __future__ import annotations

import json
import os
from typing import Any


def write_change_report(
    out_dir: str,
    *,
    target: str,
    changes: dict[str, Any],
    inventory_scores: dict[str, Any],
    change_scores: dict[str, Any],
) -> tuple[str, str]:
    """
    Persist:
      - changes.json  (machine-readable)
      - changes.md    (human "change since last scan" report)
    """
    payload = {
        "target": target,
        "changes": changes,
        "inventory_scoring": {
            "overall_score": inventory_scores.get("overall_score"),
            "max_severity": inventory_scores.get("max_severity"),
            "top_findings": (inventory_scores.get("findings") or [])[:15],
        },
        "change_scoring": change_scores,
    }

    json_path = os.path.join(out_dir, "changes.json")
    md_path = os.path.join(out_dir, "changes.md")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(_render_markdown(target, changes, inventory_scores, change_scores))

    return json_path, md_path


def _section(title: str, items: list[str]) -> str:
    if not items:
        return f"### {title}\n\n_None_\n\n"
    body = "\n".join(f"- `{i}`" for i in items)
    return f"### {title}\n\n{body}\n\n"


def _render_markdown(
    target: str,
    changes: dict[str, Any],
    inventory_scores: dict[str, Any],
    change_scores: dict[str, Any],
) -> str:
    baseline = changes.get("baseline")
    lines = [
        f"# Change since last scan — `{target}`",
        "",
        f"- Previous: `{changes.get('previous_scanned_at') or 'n/a (first scan)'}`",
        f"- Current: `{changes.get('current_scanned_at')}`",
        f"- Inventory severity: **{inventory_scores.get('max_severity', 'info')}** "
        f"(score {inventory_scores.get('overall_score', 0)})",
        f"- Change severity: **{change_scores.get('max_severity', 'info')}** "
        f"(score {change_scores.get('change_score', 0)})",
        "",
    ]

    if baseline:
        lines += [
            "## Baseline",
            "",
            "First inventory for this target — nothing to diff yet. "
            "Re-run later to get a change report.",
            "",
        ]
        return "\n".join(lines)

    lines.append("## New exposure")
    lines.append("")
    lines.append(_section("New live hosts", changes.get("new_live_hosts") or []))
    lines.append(_section("New open ports", changes.get("new_ports") or []))
    lines.append(_section("New subdomains", changes.get("new_subdomains") or []))

    lines.append("## Removed / gone quiet")
    lines.append("")
    lines.append(_section("Removed live hosts", changes.get("removed_live_hosts") or []))
    lines.append(_section("Removed open ports", changes.get("removed_ports") or []))
    lines.append(_section("Removed subdomains", changes.get("removed_subdomains") or []))

    scored = change_scores.get("items") or []
    if scored:
        lines.append("## Scored new items")
        lines.append("")
        for item in scored[:20]:
            lines.append(
                f"- **{item.get('severity', 'info').upper()}** "
                f"({item.get('score', 0)}) `{item.get('asset')}` "
                f"— {item.get('type')}"
            )
        lines.append("")

    return "\n".join(lines)
