"""Shared defaults, port profiles, and speed presets."""

from __future__ import annotations

from dataclasses import dataclass


# Learning-friendly default. Domains like example.com can return 20k+ noisy
# CT-log names; probing all of them stalls HTTPX for hours.
DEFAULT_LIMIT = 100

# Parallel workers for DNS fallback (only hosts missing IPs from HTTPX).
DNS_WORKERS = 64

# Reuse Subfinder results within this window (seconds). 0 = disabled.
DEFAULT_CACHE_TTL = 1800  # 30 minutes

# Named Nmap port profiles (advanced + fast targeting).
PORT_PROFILES: dict[str, str] = {
    "quick": "80,443",
    "web": "80,443,8080,8443,8000,8888",
    "db": "1433,1521,3306,5432,6379,27017",
    "admin": "21,22,23,25,3389,5900",
    "full": "21,22,23,25,80,110,143,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017",
}

DEFAULT_PORTS = PORT_PROFILES["web"]  # snappier default than mixed bag


@dataclass(frozen=True)
class SpeedProfile:
    """Tunable knobs for Subfinder / HTTPX / Nmap."""

    name: str
    # Subfinder
    subfinder_threads: int
    subfinder_timeout: int  # seconds per source
    subfinder_max_time: int  # minutes hard cap
    subfinder_sources: str | None  # None = default sources; set for --fast
    subfinder_max_results: int  # 0 = unlimited per source
    # HTTPX
    httpx_threads: int
    httpx_timeout: int
    httpx_retries: int
    httpx_tech_detect: bool
    # Nmap
    nmap_timing: str  # T4 / T5
    nmap_service_detect: bool
    nmap_min_rate: int
    nmap_max_retries: int


# Balanced but snappy (new default).
BALANCED = SpeedProfile(
    name="balanced",
    subfinder_threads=80,
    subfinder_timeout=10,
    subfinder_max_time=2,
    subfinder_sources="crtsh,hackertarget",
    subfinder_max_results=400,
    httpx_threads=120,
    httpx_timeout=4,
    httpx_retries=1,
    httpx_tech_detect=True,
    nmap_timing="T4",
    nmap_service_detect=False,
    nmap_min_rate=800,
    nmap_max_retries=1,
)

# Extreme speed: minimal sources, skip heavy fingerprinting.
FAST = SpeedProfile(
    name="fast",
    subfinder_threads=120,
    subfinder_timeout=5,
    subfinder_max_time=1,
    subfinder_sources="crtsh",
    subfinder_max_results=200,
    httpx_threads=200,
    httpx_timeout=2,
    httpx_retries=0,
    httpx_tech_detect=False,
    nmap_timing="T4",
    nmap_service_detect=False,
    nmap_min_rate=1500,
    nmap_max_retries=1,
)

# Thorough: slower, richer fingerprints.
DEEP = SpeedProfile(
    name="deep",
    subfinder_threads=40,
    subfinder_timeout=30,
    subfinder_max_time=5,
    subfinder_sources=None,
    subfinder_max_results=0,
    httpx_threads=60,
    httpx_timeout=10,
    httpx_retries=2,
    httpx_tech_detect=True,
    nmap_timing="T4",
    nmap_service_detect=True,
    nmap_min_rate=300,
    nmap_max_retries=2,
)


def resolve_ports(ports: str | None, profile_name: str | None) -> str:
    """Prefer --ports-profile when set; else explicit --ports; else default web."""
    if profile_name:
        key = profile_name.strip().lower()
        if key not in PORT_PROFILES:
            raise ValueError(
                f"Unknown ports profile '{profile_name}'. "
                f"Choose: {', '.join(PORT_PROFILES)}"
            )
        return PORT_PROFILES[key]
    if ports:
        return ports
    return DEFAULT_PORTS
