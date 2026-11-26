"""Pipeline phases: Subfinder → HTTPX → Nmap (speed-profile aware)."""

from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from typing import Any

from auto_recon.config import SpeedProfile
from auto_recon.core.cache import load_subdomain_cache, save_subdomain_cache
from auto_recon.core.tools import run_cmd
from auto_recon.core.ui import Ui


def ensure_priority_hosts(target: str, subdomains: list[str]) -> list[str]:
    """Always include apex + www even if Subfinder omitted them."""
    ordered: list[str] = []
    for name in (target, f"www.{target}"):
        if name not in ordered:
            ordered.append(name)
    for s in subdomains:
        if s not in ordered:
            ordered.append(s)
    return ordered


def apply_limit(ui: Ui, target: str, subdomains: list[str], limit: int) -> list[str]:
    """Cap how many hosts flow into HTTPX/Nmap; keep apex/www first."""
    subdomains = ensure_priority_hosts(target, subdomains)
    if limit <= 0 or len(subdomains) <= limit:
        return subdomains

    capped = subdomains[:limit]
    ui.warn(f"Capped subdomains to {len(capped)} (use --limit 0 for all)")
    return capped


def phase_subfinder(
    ui: Ui,
    target: str,
    out_dir: str,
    limit: int,
    profile: SpeedProfile,
    *,
    cache_ttl: int = 0,
    force_refresh: bool = False,
) -> list[str]:
    """
    Theory: Subfinder is *passive* — it queries public sources.
    Speed: limited sources + shorter timeouts under --fast.
    Cache: reuse prior subdomain lists within TTL (massive re-run speedup).
    """
    started = ui.phase_start(1, 3, "Subfinder", "enumerating subdomains…")
    subs_file = os.path.join(out_dir, "subdomains.txt")

    if not force_refresh and cache_ttl > 0:
        cached = load_subdomain_cache(out_dir, target=target, ttl_seconds=cache_ttl)
        if cached:
            unique = apply_limit(ui, target, cached, limit)
            with open(subs_file, "w", encoding="utf-8") as f:
                f.write("\n".join(unique))
                if unique:
                    f.write("\n")
            ui.phase_done("Subfinder", started, f"{len(unique)} hosts (cache hit)")
            return unique

    cmd = [
        "subfinder",
        "-d",
        target,
        "-silent",
        "-t",
        str(profile.subfinder_threads),
        "-timeout",
        str(profile.subfinder_timeout),
        "-max-time",
        str(profile.subfinder_max_time),
        "-o",
        subs_file,
    ]
    if profile.subfinder_sources:
        cmd.extend(["-sources", profile.subfinder_sources])
    if profile.subfinder_max_results > 0:
        cmd.extend(["-max-results", str(profile.subfinder_max_results)])

    run_cmd(ui, cmd, label="Subfinder")

    if not os.path.exists(subs_file):
        ui.warn("Subfinder produced no output file.")
        ui.phase_done("Subfinder", started, "0 hosts")
        return []

    with open(subs_file, encoding="utf-8") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    seen: set[str] = set()
    unique: list[str] = []
    for s in subdomains:
        key = s.lower()
        if key not in seen:
            seen.add(key)
            unique.append(key)

    # Cache full unique set before limit so later runs can re-limit differently.
    save_subdomain_cache(out_dir, target=target, subdomains=unique)
    unique = apply_limit(ui, target, unique, limit)

    with open(subs_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique))
        if unique:
            f.write("\n")

    ui.phase_done("Subfinder", started, f"{len(unique)} hosts")
    return unique


def phase_httpx(
    ui: Ui,
    subs_file: str,
    out_dir: str,
    profile: SpeedProfile,
) -> list[dict[str, Any]]:
    """
    Theory: HTTPX probes each hostname over HTTP/HTTPS.
    Speed: high -threads, short timeout; --fast skips -tech-detect.
    """
    started = ui.phase_start(2, 3, "HTTPX", "probing live hosts…")
    httpx_out = os.path.join(out_dir, "httpx.jsonl")
    if os.path.exists(httpx_out):
        os.remove(httpx_out)

    cmd = [
        "httpx",
        "-l",
        subs_file,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-ip",
        "-timeout",
        str(profile.httpx_timeout),
        "-retries",
        str(profile.httpx_retries),
        "-threads",
        str(profile.httpx_threads),
        "-o",
        httpx_out,
    ]
    if profile.httpx_tech_detect:
        cmd.append("-tech-detect")

    run_cmd(ui, cmd, label="HTTPX")

    live_hosts: list[dict[str, Any]] = []
    if not os.path.exists(httpx_out):
        ui.warn("HTTPX produced no output file.")
        ui.phase_done("HTTPX", started, "0 live")
        return live_hosts

    with open(httpx_out, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            ip_val = data.get("ip") or data.get("host_ip")
            if not ip_val:
                a_records = data.get("a") or []
                if isinstance(a_records, list) and a_records:
                    ip_val = a_records[0]
                elif isinstance(a_records, str):
                    ip_val = a_records

            live_hosts.append(
                {
                    "url": data.get("url"),
                    "host": data.get("host") or data.get("input"),
                    "ip": ip_val,
                    "status_code": data.get("status_code"),
                    "title": data.get("title"),
                    "tech": data.get("tech") or data.get("technologies") or [],
                    "webserver": data.get("webserver"),
                    "content_length": data.get("content_length"),
                    "a": data.get("a"),
                    "aaaa": data.get("aaaa"),
                }
            )

    ui.phase_done("HTTPX", started, f"{len(live_hosts)} live")
    return live_hosts


def phase_nmap(
    ui: Ui,
    ips: set[str],
    out_dir: str,
    ports: str,
    profile: SpeedProfile,
) -> str | None:
    """
    Theory: Nmap probes TCP ports; -sV is accurate but slow.
    Speed: -n (no DNS), --min-rate, skip -sV in --fast.
    Pass each IP as its own argv (more reliable than comma-lists on Windows).
    """
    started = ui.phase_start(3, 3, "Nmap", f"scanning {len(ips)} IP(s)…")
    if not ips:
        ui.warn("No IPs resolved — skipping Nmap.")
        ui.phase_done("Nmap", started, "skipped")
        return None

    nmap_xml = os.path.join(out_dir, "nmap.xml")
    cmd = [
        "nmap",
        "-Pn",
        "-n",
        f"-{profile.nmap_timing}",
        "--max-retries",
        str(profile.nmap_max_retries),
        "--min-rate",
        str(profile.nmap_min_rate),
        "-oX",
        nmap_xml,
        "-p",
        ports,
    ]
    if profile.nmap_service_detect:
        cmd[1:1] = ["-sV", "--version-intensity", "2"]
    cmd.extend(sorted(ips))

    run_cmd(ui, cmd, label="Nmap")
    ui.phase_done("Nmap", started, "scan complete")
    return nmap_xml


def parse_nmap_xml(nmap_xml: str | None) -> dict[str, list[dict[str, str]]]:
    """Walk Nmap XML and keep only open ports with service metadata."""
    findings: dict[str, list[dict[str, str]]] = {}
    if not nmap_xml or not os.path.exists(nmap_xml):
        return findings

    tree = ET.parse(nmap_xml)
    root = tree.getroot()

    for host in root.findall("host"):
        address_elem = host.find("address")
        if address_elem is None:
            continue
        ip_addr = address_elem.get("addr", "unknown")

        open_ports: list[dict[str, str]] = []
        for port in host.findall(".//port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            service_elem = port.find("service")
            open_ports.append(
                {
                    "port": port.get("portid", ""),
                    "protocol": port.get("protocol", "tcp"),
                    "service": (
                        service_elem.get("name", "unknown")
                        if service_elem is not None
                        else "unknown"
                    ),
                    "product": (
                        service_elem.get("product", "")
                        if service_elem is not None
                        else ""
                    ),
                    "version": (
                        service_elem.get("version", "")
                        if service_elem is not None
                        else ""
                    ),
                }
            )

        if open_ports:
            findings[ip_addr] = open_ports

    return findings
