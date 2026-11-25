"""Shared defaults and speed presets for the recon pipeline."""

from __future__ import annotations

from dataclasses import dataclass


# Common web / admin / DB ports for a focused first pass.
DEFAULT_PORTS = "21,22,80,443,3306,8080,8443"

# Learning-friendly default. Domains like example.com can return 20k+ noisy
# CT-log names; probing all of them stalls HTTPX for hours.
DEFAULT_LIMIT = 100

# Parallel workers for DNS fallback (only hosts missing IPs from HTTPX).
DNS_WORKERS = 64


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
    subfinder_threads=50,
    subfinder_timeout=15,
    subfinder_max_time=2,
    subfinder_sources=None,
    subfinder_max_results=0,
    httpx_threads=100,
    httpx_timeout=5,
    httpx_retries=1,
    httpx_tech_detect=True,
    nmap_timing="T4",
    nmap_service_detect=True,
    nmap_min_rate=500,
    nmap_max_retries=2,
)

# Extreme speed: limited sources, skip heavy fingerprinting.
FAST = SpeedProfile(
    name="fast",
    subfinder_threads=100,
    subfinder_timeout=6,
    subfinder_max_time=1,
    # crtsh alone is usually the fastest high-yield passive source.
    subfinder_sources="crtsh",
    subfinder_max_results=300,
    httpx_threads=150,
    httpx_timeout=3,
    httpx_retries=0,
    httpx_tech_detect=False,
    # T4 + solid rate: fast and reliable on Windows/Npcap (T5 often drops targets).
    nmap_timing="T4",
    nmap_service_detect=False,  # biggest Nmap speed win
    nmap_min_rate=1000,
    nmap_max_retries=1,
)

# Thorough: slower, richer fingerprints.
DEEP = SpeedProfile(
    name="deep",
    subfinder_threads=30,
    subfinder_timeout=30,
    subfinder_max_time=5,
    subfinder_sources=None,
    subfinder_max_results=0,
    httpx_threads=50,
    httpx_timeout=10,
    httpx_retries=2,
    httpx_tech_detect=True,
    nmap_timing="T4",
    nmap_service_detect=True,
    nmap_min_rate=200,
    nmap_max_retries=3,
)
