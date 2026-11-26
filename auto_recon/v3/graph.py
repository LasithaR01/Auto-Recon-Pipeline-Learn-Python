"""Asset graph: domain → hosts → IPs → ports (for platform views)."""

from __future__ import annotations

import json
import os
from typing import Any


def build_asset_graph(
    *,
    target: str,
    tenant_id: str | None,
    inventory: dict[str, Any] | None,
    live_hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    domain_id = f"domain:{target}"
    nodes.append({"id": domain_id, "type": "domain", "label": target, "tenant": tenant_id})

    inv_hosts = (inventory or {}).get("live_hosts") or {}
    if not inv_hosts and live_hosts:
        for h in live_hosts:
            name = (h.get("host") or "").lower()
            if name:
                inv_hosts[name] = h

    for host, meta in inv_hosts.items():
        hid = f"host:{host}"
        nodes.append(
            {
                "id": hid,
                "type": "host",
                "label": host,
                "ip": meta.get("ip"),
                "status_code": meta.get("status_code"),
            }
        )
        edges.append({"from": domain_id, "to": hid, "rel": "has_host"})
        ip = meta.get("ip")
        if ip:
            iid = f"ip:{ip}"
            if not any(n["id"] == iid for n in nodes):
                nodes.append({"id": iid, "type": "ip", "label": ip})
            edges.append({"from": hid, "to": iid, "rel": "resolves_to"})

    for ip, entries in ((inventory or {}).get("ports_by_ip") or {}).items():
        iid = f"ip:{ip}"
        if not any(n["id"] == iid for n in nodes):
            nodes.append({"id": iid, "type": "ip", "label": ip})
            edges.append({"from": domain_id, "to": iid, "rel": "has_ip"})
        for e in entries:
            port = e.get("port")
            pid = f"port:{ip}:{port}"
            nodes.append(
                {
                    "id": pid,
                    "type": "port",
                    "label": f"{ip}:{port}/{e.get('protocol', 'tcp')}",
                    "service": e.get("service"),
                }
            )
            edges.append({"from": iid, "to": pid, "rel": "exposes"})

    return {
        "target": target,
        "tenant": tenant_id,
        "nodes": nodes,
        "edges": edges,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "hosts": sum(1 for n in nodes if n["type"] == "host"),
            "ports": sum(1 for n in nodes if n["type"] == "port"),
        },
    }


def save_asset_graph(out_dir: str, graph: dict[str, Any]) -> str:
    path = os.path.join(out_dir, "asset_graph.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2, ensure_ascii=False)
    return path
