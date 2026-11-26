"""
Hardening / exposure posture checks (defensive only).

This is NOT a full vulnerability scanner and does NOT exploit anything.
It looks for common exposure signals: login surfaces, security headers,
and lightweight suspicious-content heuristics.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from auto_recon.v3.httputil import fetch, pick_base_urls

LOGIN_PATHS = [
    "/login",
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/wp-admin/",
    "/user/login",
    "/signin",
    "/account/login",
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _looks_like_login(html: str) -> bool:
    low = html.lower()
    if 'type="password"' in low or "type='password'" in low:
        return True
    if re.search(r"<form[^>]*>.*(password|login|signin)", low, re.S):
        return True
    return False


def _malware_heuristics(html: str) -> list[str]:
    """Very light suspicious patterns — not antivirus / not definitive malware."""
    findings: list[str] = []
    low = html.lower()
    if "eval(atob(" in low or ("fromcharcode" in low and "eval(" in low):
        findings.append("obfuscated_js_pattern")
    if re.search(r'<iframe[^>]+src=["\']https?://', low):
        if "display:none" in low or "visibility:hidden" in low:
            findings.append("hidden_external_iframe")
    if re.search(r'<meta[^>]+http-equiv=["\']refresh["\']', low):
        findings.append("meta_refresh_present")
    if "document.write(unescape(" in low:
        findings.append("document_write_unescape")
    return findings


def analyze_posture(
    target: str,
    live_hosts: list[dict[str, Any]] | None = None,
    nmap_findings: dict[str, list[dict[str, str]]] | None = None,
) -> dict[str, Any]:
    bases = pick_base_urls(target, live_hosts)
    primary = None
    for url in bases:
        res = fetch(url, timeout=8.0)
        if res.body or res.status:
            primary = res
            if res.ok:
                break

    if primary is None:
        return {
            "target": target,
            "ok": False,
            "error": "unreachable",
            "login_surfaces": [],
            "security_headers": {},
            "suspicious_content": [],
            "risky_ports": [],
        }

    origin = _origin(primary.final_url or primary.url)
    headers = primary.headers
    present = {h: headers.get(h) for h in SECURITY_HEADERS if h in headers}
    missing = [h for h in SECURITY_HEADERS if h not in headers]

    login_surfaces: list[dict[str, Any]] = []
    if primary.body and _looks_like_login(primary.body):
        login_surfaces.append(
            {
                "url": primary.final_url or primary.url,
                "status": primary.status,
                "signal": "password_form_on_homepage",
            }
        )

    for path in LOGIN_PATHS:
        url = origin.rstrip("/") + path
        r = fetch(url, timeout=5.0, max_bytes=80_000)
        if r.status and r.status < 400 and r.body and _looks_like_login(r.body):
            login_surfaces.append(
                {
                    "url": r.final_url or url,
                    "status": r.status,
                    "signal": "login_form",
                }
            )
        elif r.status in (200, 301, 302, 401, 403) and any(
            key in path for key in ("admin", "login", "wp-login", "signin")
        ):
            login_surfaces.append(
                {
                    "url": r.final_url or url,
                    "status": r.status,
                    "signal": "admin_or_login_path_reachable",
                }
            )

    uniq: dict[str, dict[str, Any]] = {}
    for item in login_surfaces:
        uniq[item["url"]] = item
    login_surfaces = list(uniq.values())

    suspicious = _malware_heuristics(primary.body or "")

    risky_ports: list[dict[str, str]] = []
    risky_set = {"21", "22", "23", "445", "1433", "3306", "3389", "5432", "6379", "27017"}
    for ip, entries in (nmap_findings or {}).items():
        for e in entries:
            port = str(e.get("port", ""))
            if port in risky_set:
                risky_ports.append(
                    {
                        "ip": ip,
                        "port": port,
                        "service": e.get("service", "unknown"),
                    }
                )

    https_ok = (primary.final_url or primary.url).startswith("https://")

    return {
        "target": target,
        "ok": True,
        "homepage_url": primary.final_url or primary.url,
        "https": https_ok,
        "security_headers": {
            "present": present,
            "missing": missing,
            "score": max(0, 100 - 14 * len(missing)),
        },
        "login_surfaces": login_surfaces,
        "suspicious_content": suspicious,
        "risky_ports": risky_ports,
        "notes": [
            "Hardening/exposure signals only — not a full vulnerability assessment.",
            "Suspicious-content heuristics can false-positive; verify manually.",
        ],
    }
