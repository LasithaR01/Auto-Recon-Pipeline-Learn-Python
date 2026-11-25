"""Fast IP collection: prefer HTTPX IPs, DNS only as fallback."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from auto_recon.config import DNS_WORKERS


def _clean_hostname(hostname: str) -> str:
    return (
        hostname.replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
        .split(":")[0]
    )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_httpx_ip(host: dict[str, Any]) -> str | None:
    """
    Reuse IPs already discovered by HTTPX (avoids a full DNS round-trip).

    HTTPX JSON commonly includes `a` / `aaaa` lists or an `host` that is already an IP.
    """
    for key in ("ip", "host"):
        val = host.get(key)
        if isinstance(val, str) and _is_ip(_clean_hostname(val)):
            return _clean_hostname(val)

    for key in ("a", "aaaa", "host_ip"):
        val = host.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and _is_ip(item):
                    return item
        elif isinstance(val, str) and _is_ip(val):
            return val
    return None


def _resolve_one(hostname: str) -> tuple[str, str | None]:
    try:
        return hostname, socket.gethostbyname(hostname)
    except socket.gaierror:
        return hostname, None


def resolve_ips(live_hosts: list[dict[str, Any]], workers: int = DNS_WORKERS) -> set[str]:
    """
    Collect unique IPs for Nmap as fast as possible.

    1) Prefer IPs embedded in HTTPX results (no DNS wait).
    2) Parallel DNS only for hosts still missing an IP.
    """
    ips: set[str] = set()
    need_dns: dict[str, list[dict[str, Any]]] = {}

    for host in live_hosts:
        known = _extract_httpx_ip(host)
        if known:
            host["ip"] = known
            ips.add(known)
            continue

        raw = host.get("host")
        if not raw:
            host["ip"] = None
            continue
        hostname = _clean_hostname(str(raw))
        if _is_ip(hostname):
            host["ip"] = hostname
            ips.add(hostname)
            continue
        need_dns.setdefault(hostname, []).append(host)

    if not need_dns:
        return ips

    names = list(need_dns.keys())
    worker_count = max(1, min(workers, len(names)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(_resolve_one, name) for name in names]
        for fut in as_completed(futures):
            hostname, ip = fut.result()
            for host in need_dns.get(hostname, []):
                host["ip"] = ip
            if ip:
                ips.add(ip)

    return ips
