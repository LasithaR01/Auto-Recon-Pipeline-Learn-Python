"""Uptime probing + optional watch loop (configurable interval)."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable

from auto_recon.v3.httputil import fetch, pick_base_urls


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_uptime(
    target: str,
    live_hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """One-shot uptime check against preferred live URLs."""
    results = []
    up = 0
    for url in pick_base_urls(target, live_hosts):
        res = fetch(url, timeout=6.0, method="GET")
        entry = {
            "url": url,
            "up": bool(res.ok and res.status and res.status < 500),
            "status": res.status,
            "elapsed_ms": res.elapsed_ms,
            "error": res.error,
            "final_url": res.final_url,
        }
        if entry["up"]:
            up += 1
        results.append(entry)

    overall_up = up > 0
    return {
        "checked_at": _utc_now(),
        "target": target,
        "overall_up": overall_up,
        "up_count": up,
        "checked": len(results),
        "results": results,
    }


def append_uptime_history(out_dir: str, snapshot: dict[str, Any]) -> str:
    path = os.path.join(out_dir, "uptime_history.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot, ensure_ascii=False) + "\n")
    return path


def save_uptime(out_dir: str, snapshot: dict[str, Any]) -> str:
    path = os.path.join(out_dir, "uptime.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)
    append_uptime_history(out_dir, snapshot)
    return path


def watch_uptime(
    target: str,
    out_dir: str,
    *,
    interval: float,
    live_hosts: list[dict[str, Any]] | None = None,
    on_tick: Callable[[dict[str, Any]], None] | None = None,
    on_down: Callable[[dict[str, Any]], None] | None = None,
    max_ticks: int | None = None,
) -> None:
    """
    Continuously probe uptime.

    interval can be 1 second (aggressive). Prefer 15–60s for production sites.
    """
    if interval < 1:
        interval = 1.0
    prev_up: bool | None = None
    ticks = 0
    while True:
        snap = check_uptime(target, live_hosts)
        save_uptime(out_dir, snap)
        if on_tick:
            on_tick(snap)
        if prev_up is True and snap["overall_up"] is False and on_down:
            on_down(snap)
        prev_up = bool(snap["overall_up"])
        ticks += 1
        if max_ticks is not None and ticks >= max_ticks:
            break
        time.sleep(interval)
