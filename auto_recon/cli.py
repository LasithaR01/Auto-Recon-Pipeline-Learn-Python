"""CLI entry: argparse + pipeline orchestration (v2.1)."""

from __future__ import annotations

import argparse
import os
import sys
import time

from auto_recon import APP_NAME, APP_VERSION
from auto_recon.config import (
    BALANCED,
    DEEP,
    DEFAULT_CACHE_TTL,
    DEFAULT_LIMIT,
    DEFAULT_PORTS,
    FAST,
    PORT_PROFILES,
    resolve_ports,
)
from auto_recon.core.dns import resolve_ips
from auto_recon.core.tools import require_tool, tool_version_line
from auto_recon.core.ui import Ui
from auto_recon.v1.phases import (
    parse_nmap_xml,
    phase_httpx,
    phase_nmap,
    phase_subfinder,
)
from auto_recon.v1.report import collect_open_ports, write_report
from auto_recon.v2.alerts import dispatch_alerts, resolve_webhooks
from auto_recon.v2.change_report import write_change_report
from auto_recon.v2.dashboard import write_html_dashboard
from auto_recon.v2.diffing import diff_inventories
from auto_recon.v2.export_csv import write_inventory_csv
from auto_recon.v2.inventory import (
    build_inventory,
    load_previous_inventory,
    save_inventory,
)
from auto_recon.v2.scoring import score_changes, score_inventory
from auto_recon.v3.alerts_bridge import alert_uptime_down
from auto_recon.v3.platform import run_platform
from auto_recon.v3.uptime import watch_uptime


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m auto_recon",
        description=(
            f"{APP_NAME} {APP_VERSION} — Continuous Exposure Platform "
            "(v1 recon + v2 insight + v3 monitoring)"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Authorized testing only. Lean principle: only controls that change risk posture. "
            "Webhooks: AUTO_RECON_SLACK_WEBHOOK / AUTO_RECON_TEAMS_WEBHOOK / AUTO_RECON_TICKET_WEBHOOK. "
            f"Port profiles: {', '.join(PORT_PROFILES)}"
        ),
    )
    parser.add_argument("target", help="Bare domain, e.g. example.com")
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Max subdomains to probe (0 = no cap)",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help=f"Nmap port list (default web profile: {DEFAULT_PORTS})",
    )
    parser.add_argument(
        "--ports-profile",
        choices=sorted(PORT_PROFILES.keys()),
        default=None,
        help="Named port set: quick|web|db|admin|full",
    )
    speed = parser.add_mutually_exclusive_group()
    speed.add_argument(
        "--fast",
        action="store_true",
        help="Extreme speed preset (recommended for labs)",
    )
    speed.add_argument(
        "--deep",
        action="store_true",
        help="Thorough mode: richer fingerprints, slower",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_CACHE_TTL,
        help="Reuse Subfinder cache for N seconds (0 disables)",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore Subfinder cache and re-enumerate",
    )
    parser.add_argument(
        "--skip-subfinder",
        action="store_true",
        help="Reuse existing subdomains.txt only (no Subfinder call)",
    )
    parser.add_argument(
        "--skip-httpx",
        action="store_true",
        help="Skip HTTP probing",
    )
    parser.add_argument(
        "--skip-nmap",
        action="store_true",
        help="Skip port scanning",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Do not write dashboard.html",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Do not write assets.csv",
    )
    parser.add_argument(
        "--slack-webhook",
        default=None,
        help="Slack incoming webhook URL (overrides env)",
    )
    parser.add_argument(
        "--teams-webhook",
        default=None,
        help="Teams incoming webhook URL (overrides env)",
    )
    parser.add_argument(
        "--no-alert",
        action="store_true",
        help="Do not send Slack/Teams alerts even if webhooks are set",
    )
    parser.add_argument(
        "--platform",
        action="store_true",
        default=True,
        help="Enable v3 Continuous Exposure Platform (default on)",
    )
    parser.add_argument(
        "--no-platform",
        action="store_true",
        help="Disable v3 platform pack",
    )
    parser.add_argument(
        "--tenant",
        default="default",
        help="Multi-tenant id for v3 platform",
    )
    parser.add_argument(
        "--owner",
        default=None,
        help="Asset owner for ownership mapping / tickets",
    )
    parser.add_argument(
        "--ticket-webhook",
        default=None,
        help="POST open SLA tickets JSON here (or AUTO_RECON_TICKET_WEBHOOK)",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Continuous uptime watch loop after scan (v3)",
    )
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=15.0,
        help="Uptime poll seconds (1 = every second; prefer 15–60 in prod)",
    )
    parser.add_argument(
        "--watch-ticks",
        type=int,
        default=0,
        help="Stop watch after N ticks (0 = until Ctrl+C)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show underlying tool commands",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Minimal output (prints report path only)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    return parser.parse_args()


def select_profile(args: argparse.Namespace):
    if args.fast:
        return FAST
    if args.deep:
        return DEEP
    return BALANCED


def _load_existing_subdomains(out_dir: str) -> list[str]:
    path = os.path.join(out_dir, "subdomains.txt")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]


def _run_v2_postprocess(
    ui: Ui,
    *,
    target: str,
    out_dir: str,
    subdomains: list[str],
    live_hosts: list,
    nmap_findings: dict,
    profile_name: str,
    args: argparse.Namespace,
) -> dict:
    """Inventory → diff → score → exports → optional alerts."""
    previous = load_previous_inventory(out_dir)
    inventory = build_inventory(
        target=target,
        subdomains=subdomains,
        live_hosts=live_hosts,
        nmap_findings=nmap_findings,
        profile=profile_name,
    )
    changes = diff_inventories(previous, inventory)
    inv_scores = score_inventory(inventory)
    chg_scores = score_changes(changes)

    inventory["scoring"] = {
        "overall_score": inv_scores["overall_score"],
        "max_severity": inv_scores["max_severity"],
    }
    inv_path = save_inventory(out_dir, inventory)
    changes_json, changes_md = write_change_report(
        out_dir,
        target=target,
        changes=changes,
        inventory_scores=inv_scores,
        change_scores=chg_scores,
    )

    dashboard_path = None
    if not args.no_dashboard:
        dashboard_path = write_html_dashboard(
            out_dir,
            target=target,
            inventory=inventory,
            changes=changes,
            inventory_scores=inv_scores,
            change_scores=chg_scores,
        )

    csv_path = None
    if not args.no_csv:
        csv_path = write_inventory_csv(out_dir, inventory)

    alert_results: list[dict[str, str]] = []
    if not args.no_alert:
        hooks = resolve_webhooks(args.slack_webhook, args.teams_webhook)
        alert_results = dispatch_alerts(
            target=target,
            changes=changes,
            change_scores=chg_scores,
            webhooks=hooks,
        )

    platform = None
    enable_platform = bool(args.platform) and not bool(getattr(args, "no_platform", False))
    if enable_platform:
        ticket_hook = args.ticket_webhook or os.environ.get(
            "AUTO_RECON_TICKET_WEBHOOK", ""
        ).strip() or None
        started = ui.phase_start(4, 4, "Platform", "v3 continuous exposure…")
        platform = run_platform(
            out_dir,
            target=target,
            tenant_id=args.tenant,
            owner=args.owner,
            live_hosts=live_hosts,
            nmap_findings=nmap_findings,
            inventory=inventory,
            inventory_scores=inv_scores,
            ticket_webhook=ticket_hook,
        )
        risk = platform.get("exposure_risk") or {}
        ui.phase_done(
            "Platform",
            started,
            f"risk={risk.get('level')} score={risk.get('exposure_risk_score')} "
            f"sla_fail={platform.get('sla_failing')} tickets={platform.get('tickets_open')}",
        )

    if not ui.quiet:
        if changes.get("baseline"):
            ui.info("v2: baseline inventory saved (no previous scan to diff)")
        else:
            summary = changes.get("summary") or {}
            ui.info(
                "v2: change since last scan — "
                f"new hosts={summary.get('new_live_hosts', 0)}, "
                f"new ports={summary.get('new_ports', 0)}, "
                f"severity={chg_scores.get('max_severity')}"
            )
        if dashboard_path:
            ui.info(f"dashboard → {dashboard_path}")
        if platform and platform.get("executive_path"):
            ui.info(f"executive → {platform['executive_path']}")
        for row in alert_results:
            if row["status"] == "ok":
                ui.ok(f"Alert sent → {row['channel']}")
            else:
                ui.warn(f"Alert failed → {row['channel']}: {row['detail']}")

    return {
        "inventory": inventory,
        "inventory_path": inv_path,
        "changes_json": changes_json,
        "changes_md": changes_md,
        "dashboard_path": dashboard_path,
        "csv_path": csv_path,
        "inventory_scores": inv_scores,
        "change_scores": chg_scores,
        "changes": changes,
        "alert_results": alert_results,
        "platform": platform,
    }


def main() -> None:
    args = parse_args()
    profile = select_profile(args)
    ui = Ui(
        verbose=args.verbose,
        quiet=args.quiet,
        color=not args.no_color,
    )

    target = args.target.strip().lower()
    if "://" in target or "/" in target:
        ui.err("Pass a bare domain only, e.g. example.com")
        sys.exit(1)

    try:
        ports = resolve_ports(args.ports, args.ports_profile)
    except ValueError as exc:
        ui.err(str(exc))
        sys.exit(2)

    needed = []
    if not args.skip_subfinder:
        needed.append("subfinder")
    if not args.skip_httpx:
        needed.append("httpx")
    if not args.skip_nmap:
        needed.append("nmap")
    for tool in needed:
        require_tool(ui, tool)

    out_dir = os.path.join("recon_output", target)
    os.makedirs(out_dir, exist_ok=True)

    ui.banner(target, args.limit, profile=profile.name)
    if not ui.quiet and ui.verbose:
        ui.info(f"Output: {out_dir}")
        ui.info(f"Ports: {ports}")
        ui.info(f"Cache TTL: {args.cache_ttl}s  refresh={args.refresh}")
        ui.info(
            f"Profile: {profile.name} "
            f"(httpx={profile.httpx_threads}t/{profile.httpx_timeout}s, "
            f"nmap=-{profile.nmap_timing}, sV={profile.nmap_service_detect})"
        )
        for tool in ("subfinder", "httpx", "nmap"):
            ui.info(f"{tool}: {tool_version_line(tool)}")
        print()

    total_started = time.perf_counter()
    try:
        if args.skip_subfinder:
            started = ui.phase_start(1, 3, "Subfinder", "skipped (reuse file)…")
            subdomains = _load_existing_subdomains(out_dir)
            ui.phase_done("Subfinder", started, f"{len(subdomains)} hosts (file)")
        else:
            subdomains = phase_subfinder(
                ui,
                target,
                out_dir,
                args.limit,
                profile,
                cache_ttl=args.cache_ttl,
                force_refresh=args.refresh,
            )

        live_hosts: list = []
        ips: set[str] = set()
        nmap_findings: dict = {}

        if not subdomains:
            ui.warn("No subdomains found — still writing v2 artifacts.")
        else:
            subs_file = os.path.join(out_dir, "subdomains.txt")
            if args.skip_httpx:
                started = ui.phase_start(2, 3, "HTTPX", "skipped…")
                ui.phase_done("HTTPX", started, "skipped")
            else:
                live_hosts = phase_httpx(ui, subs_file, out_dir, profile)
                ips = resolve_ips(live_hosts)

            if args.skip_nmap:
                started = ui.phase_start(3, 3, "Nmap", "skipped…")
                ui.phase_done("Nmap", started, "skipped")
            else:
                if not ips:
                    # From httpx results, or a tiny stub list if httpx was skipped.
                    seed = live_hosts or [{"host": s} for s in subdomains[:5]]
                    ips = resolve_ips(seed)
                nmap_xml = phase_nmap(
                    ui, ips, out_dir, ports=ports, profile=profile
                )
                nmap_findings = parse_nmap_xml(nmap_xml)

        v2 = _run_v2_postprocess(
            ui,
            target=target,
            out_dir=out_dir,
            subdomains=subdomains,
            live_hosts=live_hosts,
            nmap_findings=nmap_findings,
            profile_name=profile.name,
            args=args,
        )

        report_path = write_report(
            target,
            out_dir,
            subdomains,
            live_hosts,
            nmap_findings,
            profile=profile.name,
            extra={
                "v2": {
                    "inventory": "inventory.json",
                    "changes": "changes.json",
                    "changes_md": "changes.md",
                    "dashboard": "dashboard.html" if v2.get("dashboard_path") else None,
                    "csv": "assets.csv" if v2.get("csv_path") else None,
                    "overall_severity": v2["inventory_scores"].get("max_severity"),
                    "overall_score": v2["inventory_scores"].get("overall_score"),
                    "change_severity": v2["change_scores"].get("max_severity"),
                    "change_score": v2["change_scores"].get("change_score"),
                    "baseline": bool(v2["changes"].get("baseline")),
                }
            },
        )

        plat = v2.get("platform") or {}
        risk = plat.get("exposure_risk") or {}
        extra = [
            (
                "Severity",
                f"{v2['inventory_scores'].get('max_severity')} "
                f"({v2['inventory_scores'].get('overall_score')})",
            ),
            ("Inventory", v2["inventory_path"]),
            ("Changes", v2["changes_json"]),
            ("Change MD", v2["changes_md"]),
        ]
        if v2.get("dashboard_path"):
            extra.append(("Dashboard", v2["dashboard_path"]))
        if v2.get("csv_path"):
            extra.append(("CSV", v2["csv_path"]))
        if plat:
            extra.extend(
                [
                    (
                        "Risk",
                        f"{risk.get('level')} ({risk.get('exposure_risk_score')})",
                    ),
                    ("Monitor", (plat.get("monitor") or {}).get("paths", {}).get("json", "")),
                    ("Executive", plat.get("executive_path") or ""),
                    ("Platform", plat.get("platform_path") or ""),
                    ("Graph", plat.get("graph_path") or ""),
                    ("SLA", plat.get("sla_path") or ""),
                    ("Tickets", plat.get("tickets_path") or ""),
                ]
            )

        ui.summary(
            subdomains=len(subdomains),
            live_hosts=len(live_hosts),
            ips=len(ips),
            open_ports=collect_open_ports(nmap_findings),
            report_path=report_path,
            extra_rows=extra,
        )
        if not ui.quiet:
            total = time.perf_counter() - total_started
            ui.ok(f"Total runtime {total:.1f}s  [{profile.name}]  {APP_VERSION}")
            print()

        if args.watch:
            ui.info(
                f"v3 watch: uptime every {args.watch_interval}s "
                "(Ctrl+C to stop)"
            )

            def _tick(snap: dict) -> None:
                state = "UP" if snap.get("overall_up") else "DOWN"
                ui.info(f"uptime {state}  {snap.get('up_count')}/{snap.get('checked')}")

            def _down(snap: dict) -> None:
                ui.warn("uptime DOWN — sending alerts if configured")
                if not args.no_alert:
                    for row in alert_uptime_down(
                        target,
                        snap,
                        slack=args.slack_webhook,
                        teams=args.teams_webhook,
                    ):
                        if row["status"] == "ok":
                            ui.ok(f"Uptime alert → {row['channel']}")
                        else:
                            ui.warn(f"Uptime alert failed → {row['channel']}")

            watch_uptime(
                target,
                out_dir,
                interval=args.watch_interval,
                live_hosts=live_hosts,
                on_tick=_tick,
                on_down=_down,
                max_ticks=(args.watch_ticks or None),
            )
    except KeyboardInterrupt:
        print()
        ui.warn("Cancelled by user.")
        sys.exit(130)
