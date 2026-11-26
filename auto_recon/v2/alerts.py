"""Slack / Microsoft Teams webhook alerts for new exposure."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def _env_webhook(name: str) -> str | None:
    val = os.environ.get(name, "").strip()
    return val or None


def resolve_webhooks(
    slack: str | None = None,
    teams: str | None = None,
) -> dict[str, str]:
    """CLI flags override env: AUTO_RECON_SLACK_WEBHOOK / AUTO_RECON_TEAMS_WEBHOOK."""
    hooks: dict[str, str] = {}
    slack_url = (slack or "").strip() or _env_webhook("AUTO_RECON_SLACK_WEBHOOK")
    teams_url = (teams or "").strip() or _env_webhook("AUTO_RECON_TEAMS_WEBHOOK")
    if slack_url:
        hooks["slack"] = slack_url
    if teams_url:
        hooks["teams"] = teams_url
    return hooks


def _post_json(url: str, payload: dict[str, Any], timeout: int = 12) -> tuple[bool, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if 200 <= getattr(resp, "status", 200) < 300:
                return True, body or "ok"
            return False, f"HTTP {resp.status}: {body}"
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return False, f"HTTP {exc.code}: {detail}"
    except Exception as exc:  # network / SSL / timeout
        return False, str(exc)


def build_alert_text(
    *,
    target: str,
    changes: dict[str, Any],
    change_scores: dict[str, Any],
) -> str:
    summary = changes.get("summary") or {}
    lines = [
        f"Auto-Recon alert — new exposure on `{target}`",
        f"Severity: {change_scores.get('max_severity', 'info').upper()} "
        f"(score {change_scores.get('change_score', 0)})",
        f"New hosts: {summary.get('new_live_hosts', 0)} · "
        f"New ports: {summary.get('new_ports', 0)} · "
        f"New subs: {summary.get('new_subdomains', 0)}",
    ]
    new_ports = (changes.get("new_ports") or [])[:8]
    new_hosts = (changes.get("new_live_hosts") or [])[:8]
    if new_hosts:
        lines.append("Hosts: " + ", ".join(new_hosts))
    if new_ports:
        lines.append("Ports: " + ", ".join(new_ports))
    return "\n".join(lines)


def send_slack(webhook: str, text: str) -> tuple[bool, str]:
    return _post_json(webhook, {"text": text})


def send_teams(webhook: str, text: str, target: str) -> tuple[bool, str]:
    # Simple MessageCard-compatible payload (Incoming Webhook).
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": f"Auto-Recon new exposure: {target}",
        "themeColor": "FF0000",
        "title": f"Auto-Recon — new exposure on {target}",
        "text": text.replace("\n", "<br/>"),
    }
    return _post_json(webhook, payload)


def dispatch_alerts(
    *,
    target: str,
    changes: dict[str, Any],
    change_scores: dict[str, Any],
    webhooks: dict[str, str],
) -> list[dict[str, str]]:
    """
    Notify configured channels when has_new_exposure is true.
    Returns per-channel status rows for the CLI summary.
    """
    if not change_scores.get("has_new_exposure"):
        return []
    if not webhooks:
        return []

    text = build_alert_text(
        target=target, changes=changes, change_scores=change_scores
    )
    results: list[dict[str, str]] = []

    if "slack" in webhooks:
        ok, detail = send_slack(webhooks["slack"], text)
        results.append(
            {
                "channel": "slack",
                "status": "ok" if ok else "error",
                "detail": detail[:200],
            }
        )
    if "teams" in webhooks:
        ok, detail = send_teams(webhooks["teams"], text, target)
        results.append(
            {
                "channel": "teams",
                "status": "ok" if ok else "error",
                "detail": detail[:200],
            }
        )
    return results
