"""Optional uptime-down alerts via existing Slack/Teams webhooks."""

from __future__ import annotations

from typing import Any

from auto_recon.v2.alerts import resolve_webhooks, send_slack, send_teams


def alert_uptime_down(
    target: str,
    snapshot: dict[str, Any],
    *,
    slack: str | None = None,
    teams: str | None = None,
) -> list[dict[str, str]]:
    hooks = resolve_webhooks(slack, teams)
    if not hooks:
        return []
    text = (
        f"Auto-Recon uptime alert — `{target}` looks DOWN\n"
        f"Checked: {snapshot.get('checked_at')}\n"
        f"Results: {snapshot.get('up_count')}/{snapshot.get('checked')} up"
    )
    out: list[dict[str, str]] = []
    if "slack" in hooks:
        ok, detail = send_slack(hooks["slack"], text)
        out.append({"channel": "slack", "status": "ok" if ok else "error", "detail": detail[:200]})
    if "teams" in hooks:
        ok, detail = send_teams(hooks["teams"], text, target)
        out.append({"channel": "teams", "status": "ok" if ok else "error", "detail": detail[:200]})
    return out
