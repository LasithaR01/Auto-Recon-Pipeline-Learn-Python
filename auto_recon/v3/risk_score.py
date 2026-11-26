"""
Exposure / hardening risk score (defensive).

Higher score = more exposure / weaker hardening signals observed.
This is NOT a prediction that a site “can be hacked”, and NOT exploit output.
"""

from __future__ import annotations

from typing import Any


def _level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def compute_exposure_risk(
    *,
    uptime: dict[str, Any] | None,
    health: dict[str, Any] | None,
    posture: dict[str, Any] | None,
    inventory_scores: dict[str, Any] | None = None,
) -> dict[str, Any]:
    score = 0
    factors: list[dict[str, Any]] = []

    def add(points: int, code: str, detail: str) -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        factors.append({"points": points, "code": code, "detail": detail})

    if uptime and not uptime.get("overall_up", True):
        add(25, "downtime", "Site failed uptime checks")

    if health:
        broken = int(health.get("broken_count") or 0)
        if broken:
            add(min(20, broken * 3), "broken_pages", f"{broken} broken internal link(s)")
        seo = health.get("seo") or {}
        issues = seo.get("issues") or []
        if issues:
            add(min(15, 3 * len(issues)), "seo_gaps", f"SEO issues: {', '.join(issues[:6])}")

    if posture:
        if not posture.get("https", True):
            add(20, "no_https", "Primary URL is not HTTPS")
        missing = (posture.get("security_headers") or {}).get("missing") or []
        if missing:
            add(
                min(24, 4 * len(missing)),
                "missing_headers",
                f"Missing security headers: {', '.join(missing[:6])}",
            )
        logins = posture.get("login_surfaces") or []
        if logins:
            add(
                min(20, 5 * len(logins)),
                "login_surfaces",
                f"{len(logins)} reachable login/admin surface(s)",
            )
        suspicious = posture.get("suspicious_content") or []
        if suspicious:
            add(
                min(25, 10 * len(suspicious)),
                "suspicious_content",
                f"Heuristic flags: {', '.join(suspicious)}",
            )
        risky_ports = posture.get("risky_ports") or []
        if risky_ports:
            add(
                min(30, 8 * len(risky_ports)),
                "risky_ports",
                f"{len(risky_ports)} sensitive port(s) exposed",
            )

    # Blend a little inventory severity if present
    if inventory_scores:
        inv = int(inventory_scores.get("overall_score") or 0)
        bump = min(15, inv // 10)
        if bump:
            add(bump, "inventory_blend", "Inventory severity contributed to exposure score")

    score = max(0, min(100, score))
    return {
        "exposure_risk_score": score,
        "level": _level(score),
        "interpretation": (
            "Higher = more public exposure / weaker hardening signals. "
            "Not a guarantee of compromise and not a full vuln scan."
        ),
        "factors": sorted(factors, key=lambda f: -f["points"]),
        "disclaimer": (
            "Authorized defensive monitoring only. "
            "Do not use these signals to attack systems you do not own."
        ),
    }
