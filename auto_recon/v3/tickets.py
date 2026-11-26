"""Ticketing integration (file + optional webhook) for failed SLAs / risk."""

from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_tickets_from_sla(
    *,
    target: str,
    tenant_id: str | None,
    sla: dict[str, Any],
    ownership: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Open tickets only for failed controls that change risk posture."""
    owner = (ownership or {}).get("default_owner") or "unassigned"
    tickets = []
    for item in sla.get("items") or []:
        if item.get("status") != "fail":
            continue
        tickets.append(
            {
                "id": f"{target}-{item.get('id')}-{_utc_now()}",
                "created_at": _utc_now(),
                "target": target,
                "tenant": tenant_id,
                "title": item.get("title"),
                "control": item.get("control"),
                "detail": item.get("detail"),
                "priority": "high",
                "owner": owner,
                "status": "open",
            }
        )
    return tickets


def save_tickets(out_dir: str, tickets: list[dict[str, Any]]) -> str:
    path = os.path.join(out_dir, "tickets.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"tickets": tickets}, f, indent=2, ensure_ascii=False)
    # Append history for platform audit
    hist = os.path.join(out_dir, "tickets_history.jsonl")
    with open(hist, "a", encoding="utf-8") as f:
        for t in tickets:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")
    return path


def push_tickets_webhook(url: str, tickets: list[dict[str, Any]]) -> tuple[bool, str]:
    if not tickets:
        return True, "no tickets"
    payload = json.dumps({"source": "auto-recon-v3", "tickets": tickets}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            return True, f"HTTP {getattr(resp, 'status', 200)}"
    except Exception as exc:
        return False, str(exc)
