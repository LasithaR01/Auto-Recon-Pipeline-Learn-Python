"""
Auto-Recon (v1) — Windows-friendly recon pipeline orchestrator.

Pipeline:
  1. Subfinder  → passive subdomain enumeration
  2. HTTPX      → live-host probe + tech fingerprint
  3. Nmap       → port / service scan on resolved IPs
  4. Merge      → single structured report.json

Usage (prefer Administrator PowerShell for Nmap):
  python recon.py example.com
  python recon.py example.com --limit 50
  python recon.py example.com --limit 0          # no cap (can be huge)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any


# Common web / admin / DB ports for a focused first pass (v1).
DEFAULT_PORTS = "21,22,80,443,3306,8080,8443"

# Learning-friendly default. Domains like example.com can return 20k+ noisy
# CT-log names; probing all of them stalls HTTPX for hours.
DEFAULT_LIMIT = 100


def require_tool(name: str) -> None:
    """Fail early if a CLI tool is missing from PATH."""
    if shutil.which(name) is None:
        print(f"[!] Required tool not found on PATH: {name}")
        print("    Install it and reopen the terminal, then try again.")
        sys.exit(1)


def run_cmd(cmd: list[str], *, label: str) -> None:
    """
    Run an external tool quietly.

    Theory: tools like Subfinder with -silent still echo results to stdout.
    Capturing stdout/stderr keeps the pipeline log readable; failures still
    surface via return code + a short stderr snippet.
    """
    print(f"[*] {label}")
    print(f"    $ {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        print(f"[!] Could not execute: {cmd[0]}")
        sys.exit(1)

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        if err:
            print(err[-2000:])
        print(f"[!] {label} failed with exit code {result.returncode}")
        sys.exit(result.returncode)


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


def apply_limit(target: str, subdomains: list[str], limit: int) -> list[str]:
    """
    Cap how many hosts flow into HTTPX/Nmap.

    Always prefer the apex + www first so the learning demo still hits the
    real site even when CT logs are noisy.
    """
    subdomains = ensure_priority_hosts(target, subdomains)
    if limit <= 0 or len(subdomains) <= limit:
        return subdomains

    capped = subdomains[:limit]
    print(
        f"[!] Capped subdomains to {len(capped)} "
        f"(use --limit 0 for all)"
    )
    return capped


def phase_subfinder(target: str, out_dir: str, limit: int) -> list[str]:
    """
    Theory: Subfinder is *passive* — it queries public sources (CT logs,
    DNS datasets, search engines, etc.) instead of brute-forcing names.
    That keeps noise low and is a safe first step in authorized recon.
    """
    subs_file = os.path.join(out_dir, "subdomains.txt")
    run_cmd(
        ["subfinder", "-d", target, "-silent", "-o", subs_file],
        label="Phase 1: Subdomain enumeration (Subfinder)",
    )

    with open(subs_file, encoding="utf-8") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    # De-dupe while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for s in subdomains:
        key = s.lower()
        if key not in seen:
            seen.add(key)
            unique.append(key)

    unique = apply_limit(target, unique, limit)

    with open(subs_file, "w", encoding="utf-8") as f:
        f.write("\n".join(unique))
        if unique:
            f.write("\n")

    print(f"[+] Using {len(unique)} subdomains → {subs_file}")
    return unique


def phase_httpx(subs_file: str, out_dir: str) -> list[dict[str, Any]]:
    """
    Theory: HTTPX probes each hostname over HTTP/HTTPS.
    -json writes JSONL (one JSON object per line) — easy for Python to parse.
    -tech-detect adds framework / server hints for the report.
    """
    httpx_out = os.path.join(out_dir, "httpx.jsonl")
    # Remove stale empty/partial file from a previous aborted run.
    if os.path.exists(httpx_out):
        os.remove(httpx_out)

    run_cmd(
        [
            "httpx",
            "-l",
            subs_file,
            "-silent",
            "-json",
            "-tech-detect",
            "-status-code",
            "-title",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-o",
            httpx_out,
        ],
        label="Phase 2: Live-host probe + tech detect (HTTPX)",
    )

    live_hosts: list[dict[str, Any]] = []
    if not os.path.exists(httpx_out):
        print("[!] HTTPX produced no output file.")
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

            live_hosts.append(
                {
                    "url": data.get("url"),
                    "host": data.get("host") or data.get("input"),
                    "status_code": data.get("status_code"),
                    "title": data.get("title"),
                    "tech": data.get("tech") or data.get("technologies") or [],
                    "webserver": data.get("webserver"),
                    "content_length": data.get("content_length"),
                }
            )

    print(f"[+] Found {len(live_hosts)} live HTTP(S) hosts → {httpx_out}")
    return live_hosts


def resolve_ips(live_hosts: list[dict[str, Any]]) -> set[str]:
    """
    Theory: Feeding Nmap raw IPs avoids repeated DNS lookups and keeps
    the port-scan phase tied to hosts that already answered on HTTP(S).
    """
    ips: set[str] = set()
    for host in live_hosts:
        hostname = host.get("host")
        if not hostname:
            continue
        hostname = (
            hostname.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )
        try:
            ip = socket.gethostbyname(hostname)
            ips.add(ip)
            host["ip"] = ip
        except socket.gaierror:
            host["ip"] = None
    return ips


def phase_nmap(ips: set[str], out_dir: str, ports: str = DEFAULT_PORTS) -> str | None:
    """
    Theory: Nmap actively probes TCP ports and (-sV) guesses service versions.
    -oX writes XML so we can parse open ports into the final JSON report.
    On Windows, run the terminal as Administrator for best Npcap behavior.
    """
    if not ips:
        print("[!] No IPs resolved — skipping Nmap.")
        return None

    nmap_xml = os.path.join(out_dir, "nmap.xml")
    ip_list = ",".join(sorted(ips))
    run_cmd(
        ["nmap", "-sV", "-Pn", "-oX", nmap_xml, "-p", ports, ip_list],
        label=f"Phase 3: Port scan (Nmap) on {len(ips)} IP(s)",
    )
    print(f"[+] Nmap XML saved → {nmap_xml}")
    return nmap_xml


def parse_nmap_xml(nmap_xml: str | None) -> dict[str, list[dict[str, str]]]:
    """
    Theory: XML is structured — we walk <host>/<address>/<port> and keep
    only open ports with service names for the merged report.
    """
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


def write_report(
    target: str,
    out_dir: str,
    subdomains: list[str],
    live_hosts: list[dict[str, Any]],
    nmap_findings: dict[str, list[dict[str, str]]],
) -> str:
    """Assemble the single JSON artifact that later versions can extend."""
    report = {
        "target": target,
        "version": "v1",
        "total_subdomains": len(subdomains),
        "total_live_hosts": len(live_hosts),
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "nmap_findings": nmap_findings,
    }

    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[+] Final report → {report_path}")
    return report_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto-Recon v1 — Subfinder → HTTPX → Nmap → JSON report"
    )
    parser.add_argument("target", help="Bare domain, e.g. example.com")
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"Max subdomains to probe (default {DEFAULT_LIMIT}; 0 = no cap)",
    )
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        help=f"Nmap port list (default {DEFAULT_PORTS})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    target = args.target.strip().lower()
    if "://" in target or "/" in target:
        print("[!] Pass a bare domain only, e.g. example.com")
        sys.exit(1)

    for tool in ("subfinder", "httpx", "nmap"):
        require_tool(tool)

    out_dir = os.path.join("recon_output", target)
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Auto-Recon v1 starting for: {target}")
    print(f"[*] Output directory: {out_dir}")
    print(f"[*] Subdomain limit: {args.limit if args.limit > 0 else 'none'}")
    print("-" * 50)

    subdomains = phase_subfinder(target, out_dir, args.limit)
    if not subdomains:
        print("[!] No subdomains found — pipeline stops here.")
        write_report(target, out_dir, [], [], {})
        sys.exit(0)

    subs_file = os.path.join(out_dir, "subdomains.txt")
    live_hosts = phase_httpx(subs_file, out_dir)
    ips = resolve_ips(live_hosts)
    print(f"[+] Resolved {len(ips)} unique IP(s) from live hosts.")

    nmap_xml = phase_nmap(ips, out_dir, ports=args.ports)
    nmap_findings = parse_nmap_xml(nmap_xml)

    write_report(target, out_dir, subdomains, live_hosts, nmap_findings)
    print("-" * 50)
    print("[+] Done. Review report.json before expanding scope (v2+).")


if __name__ == "__main__":
    main()
