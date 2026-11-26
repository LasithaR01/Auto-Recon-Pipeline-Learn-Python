"""Diff two inventories → change-since-last-scan structure."""

from __future__ import annotations

from typing import Any


def diff_inventories(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare previous vs current inventory.

    First scan → baseline (no previous); still returns a valid changes object.
    """
    if previous is None:
        return {
            "baseline": True,
            "previous_scanned_at": None,
            "current_scanned_at": current.get("scanned_at"),
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_live_hosts": [],
            "removed_live_hosts": [],
            "new_ports": [],
            "removed_ports": [],
            "summary": {
                "is_first_scan": True,
                "new_exposure_count": 0,
                "removed_count": 0,
            },
        }

    prev_subs = set(previous.get("subdomains") or [])
    curr_subs = set(current.get("subdomains") or [])
    prev_hosts = set((previous.get("live_hosts") or {}).keys())
    curr_hosts = set((current.get("live_hosts") or {}).keys())
    prev_ports = set(previous.get("port_index") or [])
    curr_ports = set(current.get("port_index") or [])

    new_subs = sorted(curr_subs - prev_subs)
    removed_subs = sorted(prev_subs - curr_subs)
    new_hosts = sorted(curr_hosts - prev_hosts)
    removed_hosts = sorted(prev_hosts - curr_hosts)
    new_ports = sorted(curr_ports - prev_ports)
    removed_ports = sorted(prev_ports - curr_ports)

    new_exposure = len(new_hosts) + len(new_ports)
    removed = len(removed_hosts) + len(removed_ports) + len(removed_subs)

    return {
        "baseline": False,
        "previous_scanned_at": previous.get("scanned_at"),
        "current_scanned_at": current.get("scanned_at"),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "new_live_hosts": new_hosts,
        "removed_live_hosts": removed_hosts,
        "new_ports": new_ports,
        "removed_ports": removed_ports,
        "summary": {
            "is_first_scan": False,
            "new_exposure_count": new_exposure,
            "removed_count": removed,
            "new_subdomains": len(new_subs),
            "new_live_hosts": len(new_hosts),
            "new_ports": len(new_ports),
        },
    }
