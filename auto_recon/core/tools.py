"""External CLI tool helpers (PATH checks + quiet subprocess runner)."""

from __future__ import annotations

import shutil
import subprocess
import sys

from auto_recon.core.ui import Ui


def require_tool(ui: Ui, name: str) -> None:
    """Fail early if a CLI tool is missing from PATH."""
    if shutil.which(name) is None:
        ui.err(f"Required tool not found on PATH: {name}")
        ui.info("Install it and reopen the terminal, then try again.")
        sys.exit(1)


def tool_version_line(name: str) -> str:
    """Best-effort short version string for verbose mode."""
    for flag in ("-version", "--version"):
        try:
            result = subprocess.run(
                [name, flag],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
            )
            text = (result.stdout or result.stderr or "").strip()
            if text:
                return text.splitlines()[0][:80]
        except Exception:
            continue
    return "available"


def run_cmd(ui: Ui, cmd: list[str], *, label: str) -> None:
    """
    Run an external tool quietly.

    Capturing stdout/stderr keeps the pipeline log readable; failures still
    surface via return code + a short stderr snippet.
    """
    ui.cmd(" ".join(cmd))
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
        ui.err(f"Could not execute: {cmd[0]}")
        sys.exit(1)

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        if err and not ui.quiet:
            print(ui.dim(err[-2000:]))
        ui.err(f"{label} failed with exit code {result.returncode}")
        sys.exit(result.returncode)
