"""Small stdlib HTTP helper for monitoring checks."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class HttpResult:
    url: str
    ok: bool
    status: int | None
    elapsed_ms: int
    headers: dict[str, str]
    body: str
    error: str | None = None
    final_url: str | None = None


def fetch(
    url: str,
    *,
    timeout: float = 8.0,
    method: str = "GET",
    max_bytes: int = 200_000,
) -> HttpResult:
    import time

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": "Auto-Recon-Monitor/3.0 (+authorized-testing)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_bytes)
            elapsed = int((time.perf_counter() - started) * 1000)
            headers = {k.lower(): v for k, v in dict(resp.headers).items()}
            charset = "utf-8"
            ctype = headers.get("content-type", "")
            if "charset=" in ctype:
                charset = ctype.split("charset=")[-1].split(";")[0].strip() or "utf-8"
            body = raw.decode(charset, errors="replace")
            return HttpResult(
                url=url,
                ok=True,
                status=getattr(resp, "status", 200),
                elapsed_ms=elapsed,
                headers=headers,
                body=body,
                final_url=resp.geturl(),
            )
    except urllib.error.HTTPError as exc:
        elapsed = int((time.perf_counter() - started) * 1000)
        try:
            raw = exc.read(max_bytes)
            body = raw.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        headers = {k.lower(): v for k, v in dict(exc.headers or {}).items()}
        return HttpResult(
            url=url,
            ok=False,
            status=exc.code,
            elapsed_ms=elapsed,
            headers=headers,
            body=body,
            error=f"HTTP {exc.code}",
            final_url=exc.geturl() if hasattr(exc, "geturl") else url,
        )
    except Exception as exc:
        elapsed = int((time.perf_counter() - started) * 1000)
        return HttpResult(
            url=url,
            ok=False,
            status=None,
            elapsed_ms=elapsed,
            headers={},
            body="",
            error=str(exc),
        )


def pick_base_urls(target: str, live_hosts: list[dict[str, Any]] | None = None) -> list[str]:
    """Prefer live HTTPS URLs from recon; fall back to https/http apex."""
    urls: list[str] = []
    for h in live_hosts or []:
        u = h.get("url")
        if isinstance(u, str) and u.startswith("http"):
            urls.append(u.rstrip("/") + "/")
    if not urls:
        urls = [f"https://{target}/", f"http://{target}/"]
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[:6]
