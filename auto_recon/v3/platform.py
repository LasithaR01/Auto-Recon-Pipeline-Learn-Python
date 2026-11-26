"""
v3 Continuous Exposure Platform orchestrator.

Wires monitoring + tenants + graph + ownership + SLA + tickets + executive view.
"""

from __future__ import annotations

import os
from typing import Any

from auto_recon.v3.graph import build_asset_graph, save_asset_graph
from auto_recon.v3.monitor import run_monitor
from auto_recon.v3.ownership import map_ownership
from auto_recon.v3.executive import write_executive_dashboard
from auto_recon.v3.sla import evaluate_slas, save_sla
from auto_recon.v3.tenants import get_tenant, upsert_tenant
from auto_recon.v3.tickets import (
    build_tickets_from_sla,
    push_tickets_webhook,
    save_tickets,
)


def run_platform(
    out_dir: str,
    *,
    target: str,
    tenant_id: str | None = None,
    tenant_name: str | None = None,
    owner: str | None = None,
    live_hosts: list[dict[str, Any]] | None = None,
    nmap_findings: dict[str, list[dict[str, str]]] | None = None,
    inventory: dict[str, Any] | None = None,
    inventory_scores: dict[str, Any] | None = None,
    ticket_webhook: str | None = None,
) -> dict[str, Any]:
    tid = (tenant_id or "default").strip() or "default"
    tenant = upsert_tenant(
        tid,
        name=tenant_name or tid,
        domains=[target],
        owner=owner or "unassigned",
    )

    monitor = run_monitor(
        out_dir,
        target=target,
        live_hosts=live_hosts,
        nmap_findings=nmap_findings,
        inventory_scores=inventory_scores,
    )

    graph = build_asset_graph(
        target=target,
        tenant_id=tid,
        inventory=inventory,
        live_hosts=live_hosts,
    )
    graph_path = save_asset_graph(out_dir, graph)

    ownership = map_ownership(
        out_dir,
        target=target,
        tenant_owner=tenant.get("owner"),
        inventory=inventory,
    )

    sla = evaluate_slas(monitor=monitor, inventory_scores=inventory_scores)
    sla_path = save_sla(out_dir, sla)

    tickets = build_tickets_from_sla(
        target=target,
        tenant_id=tid,
        sla=sla,
        ownership=ownership,
    )
    tickets_path = save_tickets(out_dir, tickets)

    webhook_status = None
    if ticket_webhook and tickets:
        ok, detail = push_tickets_webhook(ticket_webhook, tickets)
        webhook_status = {"ok": ok, "detail": detail}

    exec_path = write_executive_dashboard(
        out_dir,
        target=target,
        tenant=tenant,
        monitor=monitor,
        sla=sla,
        graph=graph,
        tickets=tickets,
    )

    summary = {
        "tenant": tenant,
        "monitor": monitor,
        "graph_path": graph_path,
        "ownership_path": ownership.get("path"),
        "sla_path": sla_path,
        "tickets_path": tickets_path,
        "tickets_open": len(tickets),
        "executive_path": exec_path,
        "ticket_webhook": webhook_status,
        "exposure_risk": (monitor.get("exposure_risk") or {}),
        "sla_failing": sla.get("failing", 0),
    }

    # Platform rollup for the target
    rollup_path = os.path.join(out_dir, "platform.json")
    import json

    with open(rollup_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "target": target,
                "tenant": tenant,
                "exposure_risk": summary["exposure_risk"],
                "sla_failing": summary["sla_failing"],
                "tickets_open": summary["tickets_open"],
                "paths": {
                    "monitor": (monitor.get("paths") or {}).get("json"),
                    "graph": graph_path,
                    "ownership": ownership.get("path"),
                    "sla": sla_path,
                    "tickets": tickets_path,
                    "executive": exec_path,
                },
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    summary["platform_path"] = rollup_path
    return summary
