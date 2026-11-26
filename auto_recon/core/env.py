"""Runtime environment detection for the banner / report metadata."""

from __future__ import annotations

import platform


def detect_environment() -> str:
    """Label the runtime OS (changes per machine where the code runs)."""
    system = platform.system()
    if system == "Windows":
        release = platform.release()
        version = platform.version()
        build = 0
        try:
            # version looks like: "10.0.26200"
            build = int(version.split(".")[2].split()[0])
        except (IndexError, ValueError):
            pass
        if build >= 22000 or release == "11":
            return "Windows 11"
        return f"Windows {release}"
    if system == "Darwin":
        ver = platform.mac_ver()[0] or ""
        return f"macOS {ver}".strip()
    if system == "Linux":
        return f"Linux {platform.release()}"
    return system or "Unknown"
