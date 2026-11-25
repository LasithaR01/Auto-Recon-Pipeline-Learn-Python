"""CLI entry: argparse + pipeline orchestration."""

from __future__ import annotations

import argparse
import os
import sys
import time

from auto_recon import APP_NAME, APP_VERSION
from auto_recon.config import BALANCED, DEEP, DEFAULT_LIMIT, DEFAULT_PORTS, FAST
from auto_recon.dnsutil import resolve_ips
from auto_recon.phases import parse_nmap_xml, phase_httpx, phase_nmap, phase_subfinder
from auto_recon.report import collect_open_ports, write_report
from auto_recon.tools import require_tool, tool_version_line
from auto_recon.ui import Ui


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m auto_recon",
        description=(
            f"{APP_NAME} {APP_VERSION} — Subfinder → HTTPX → Nmap → JSON report"
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="Only scan domains you own or have written authorization to test.",
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
        default=DEFAULT_PORTS,
        help="Nmap port list",
    )
    speed = parser.add_mutually_exclusive_group()
    speed.add_argument(
        "--fast",
        action="store_true",
        help="Extreme speed: skip tech/version detect, aggressive timeouts",
    )
    speed.add_argument(
        "--deep",
        action="store_true",
        help="Thorough mode: richer fingerprints, slower",
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
    return parser.parse_args()


def select_profile(args: argparse.Namespace):
    if args.fast:
        return FAST
    if args.deep:
        return DEEP
    return BALANCED


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

    for tool in ("subfinder", "httpx", "nmap"):
        require_tool(ui, tool)

    out_dir = os.path.join("recon_output", target)
    os.makedirs(out_dir, exist_ok=True)

    ui.banner(target, args.limit, profile=profile.name)
    if not ui.quiet and ui.verbose:
        ui.info(f"Output: {out_dir}")
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
        subdomains = phase_subfinder(ui, target, out_dir, args.limit, profile)
        if not subdomains:
            ui.warn("No subdomains found — pipeline stops here.")
            report_path = write_report(
                target, out_dir, [], [], {}, profile=profile.name
            )
            ui.summary(
                subdomains=0,
                live_hosts=0,
                ips=0,
                open_ports=[],
                report_path=report_path,
            )
            sys.exit(0)

        subs_file = os.path.join(out_dir, "subdomains.txt")
        live_hosts = phase_httpx(ui, subs_file, out_dir, profile)
        ips = resolve_ips(live_hosts)

        nmap_xml = phase_nmap(ui, ips, out_dir, ports=args.ports, profile=profile)
        nmap_findings = parse_nmap_xml(nmap_xml)
        report_path = write_report(
            target,
            out_dir,
            subdomains,
            live_hosts,
            nmap_findings,
            profile=profile.name,
        )

        ui.summary(
            subdomains=len(subdomains),
            live_hosts=len(live_hosts),
            ips=len(ips),
            open_ports=collect_open_ports(nmap_findings),
            report_path=report_path,
        )
        if not ui.quiet:
            total = time.perf_counter() - total_started
            ui.ok(f"Total runtime {total:.1f}s  [{profile.name}]")
            print()
    except KeyboardInterrupt:
        print()
        ui.warn("Cancelled by user.")
        sys.exit(130)
