"""Broken-page checks + basic SEO signals (defensive quality monitoring)."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from auto_recon.v3.httputil import fetch, pick_base_urls


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.title = ""
        self.meta_description = ""
        self.h1_count = 0
        self.canonical = ""
        self._in_title = False
        self._in_h1 = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        if tag == "a" and ad.get("href"):
            self.hrefs.append(ad["href"])
        elif tag == "title":
            self._in_title = True
        elif tag == "h1":
            self._in_h1 = True
            self.h1_count += 1
        elif tag == "meta" and ad.get("name", "").lower() == "description":
            self.meta_description = ad.get("content", "")
        elif tag == "link" and ad.get("rel", "").lower() == "canonical":
            self.canonical = ad.get("href", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "h1":
            self._in_h1 = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def _same_origin(base: str, link: str) -> bool:
    b, l = urlparse(base), urlparse(link)
    if not l.scheme:
        return True
    return (b.scheme, b.netloc) == (l.scheme, l.netloc)


def analyze_health(
    target: str,
    live_hosts: list[dict[str, Any]] | None = None,
    *,
    max_links: int = 25,
) -> dict[str, Any]:
    """
    Fetch homepage(s), extract same-origin links, flag broken pages,
    and compute basic SEO hygiene findings.
    """
    bases = pick_base_urls(target, live_hosts)
    homepage = None
    for url in bases:
        res = fetch(url, timeout=8.0)
        if res.ok and res.status and res.status < 400 and res.body:
            homepage = res
            break
        homepage = res

    if homepage is None:
        return {
            "target": target,
            "ok": False,
            "error": "no homepage reachable",
            "broken_pages": [],
            "seo": {},
        }

    parser = _LinkParser()
    try:
        parser.feed(homepage.body)
    except Exception:
        pass

    base = homepage.final_url or homepage.url
    candidates: list[str] = []
    seen: set[str] = set()
    for href in parser.hrefs:
        if href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        abs_url = urljoin(base, href)
        if not _same_origin(base, abs_url):
            continue
        # strip fragments
        abs_url = abs_url.split("#")[0]
        if abs_url in seen:
            continue
        seen.add(abs_url)
        candidates.append(abs_url)
        if len(candidates) >= max_links:
            break

    broken: list[dict[str, Any]] = []
    checked = 0
    for link in candidates:
        checked += 1
        r = fetch(link, timeout=6.0, method="GET", max_bytes=4096)
        status = r.status or 0
        if (not r.ok) or status >= 400:
            broken.append(
                {
                    "url": link,
                    "status": status,
                    "error": r.error,
                }
            )

    title = parser.title.strip()
    desc = parser.meta_description.strip()
    seo_issues: list[str] = []
    if not title:
        seo_issues.append("missing_title")
    elif len(title) < 10:
        seo_issues.append("title_too_short")
    elif len(title) > 70:
        seo_issues.append("title_too_long")
    if not desc:
        seo_issues.append("missing_meta_description")
    elif len(desc) < 50:
        seo_issues.append("meta_description_short")
    elif len(desc) > 160:
        seo_issues.append("meta_description_long")
    if parser.h1_count == 0:
        seo_issues.append("missing_h1")
    elif parser.h1_count > 1:
        seo_issues.append("multiple_h1")
    if not parser.canonical:
        seo_issues.append("missing_canonical")

    seo_score = max(0, 100 - 12 * len(seo_issues))
    return {
        "target": target,
        "ok": bool(homepage.ok),
        "homepage_url": homepage.final_url or homepage.url,
        "homepage_status": homepage.status,
        "links_checked": checked,
        "broken_count": len(broken),
        "broken_pages": broken,
        "seo": {
            "title": title[:120],
            "meta_description": desc[:200],
            "h1_count": parser.h1_count,
            "canonical": parser.canonical,
            "issues": seo_issues,
            "seo_score": seo_score,
        },
    }
