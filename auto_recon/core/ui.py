"""Professional terminal UI: banner, colors, phase timers, summary."""

from __future__ import annotations

import platform
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from auto_recon import APP_NAME, APP_VERSION
from auto_recon.core.env import detect_environment


def _enable_windows_ansi() -> None:
    """Enable VT100 colors in modern Windows consoles (no extra dependency)."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


@dataclass
class Ui:
    verbose: bool = False
    quiet: bool = False
    color: bool = True
    phase_stats: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.color and sys.stdout.isatty():
            _enable_windows_ansi()
        else:
            self.color = False

    def _c(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def cyan(self, t: str) -> str:
        return self._c("36", t)

    def green(self, t: str) -> str:
        return self._c("32", t)

    def yellow(self, t: str) -> str:
        return self._c("33", t)

    def red(self, t: str) -> str:
        return self._c("31", t)

    def bold(self, t: str) -> str:
        return self._c("1", t)

    def dim(self, t: str) -> str:
        return self._c("2", t)

    def info(self, msg: str) -> None:
        if self.quiet:
            return
        print(f"  {self.cyan('•')} {msg}")

    def ok(self, msg: str) -> None:
        if self.quiet:
            return
        print(f"  {self.green('✓')} {msg}")

    def warn(self, msg: str) -> None:
        if self.quiet:
            return
        print(f"  {self.yellow('!')} {msg}")

    def err(self, msg: str) -> None:
        print(f"  {self.red('✗')} {msg}", file=sys.stderr)

    def cmd(self, cmdline: str) -> None:
        if self.quiet or not self.verbose:
            return
        print(f"    {self.dim('$ ' + cmdline)}")

    def banner(self, target: str, limit: int, profile: str = "balanced") -> None:
        if self.quiet:
            return
        env = detect_environment()
        limit_label = "none" if limit <= 0 else str(limit)
        inner = 43

        def row(left: str, right: str) -> str:
            right = f"{right} "
            gap = max(1, inner - len(left) - len(right))
            return f"{left}{' ' * gap}{right}"[:inner].ljust(inner)

        line1 = row(f"  {APP_NAME}  {APP_VERSION}", env)
        line2 = row(f"  Target: {target}", f"Limit: {limit_label}")
        line3 = row(f"  Mode: {profile}", "")
        top = "┌" + "─" * inner + "┐"
        bot = "└" + "─" * inner + "┘"
        print()
        print(self.cyan(top))
        print(self.cyan("│") + self.bold(line1) + self.cyan("│"))
        print(self.cyan("│") + line2 + self.cyan("│"))
        print(self.cyan("│") + line3 + self.cyan("│"))
        print(self.cyan(bot))
        print()

    def phase_start(self, index: int, total: int, name: str, action: str) -> float:
        if not self.quiet:
            prefix = self.bold(f"[{index}/{total}]")
            label = self.cyan(f"{name:<12}")
            print(f"  {prefix} {label}  {self.dim(action)}")
        return time.perf_counter()

    def phase_done(self, name: str, started: float, detail: str) -> None:
        elapsed = time.perf_counter() - started
        self.phase_stats.append(
            {"name": name, "elapsed": elapsed, "detail": detail}
        )
        if self.quiet:
            return
        print(
            f"         {self.green('✓')}  {detail}  "
            f"{self.dim(f'{elapsed:.1f}s')}"
        )

    def summary(
        self,
        *,
        subdomains: int,
        live_hosts: int,
        ips: int,
        open_ports: list[str],
        report_path: str,
        extra_rows: list[tuple[str, str]] | None = None,
    ) -> None:
        if self.quiet:
            print(report_path)
            return
        ports_label = ", ".join(open_ports) if open_ports else "none"
        print()
        print(f"  {self.bold('── Summary ' + '─' * 28)}")
        rows: list[tuple[str, str]] = [
            ("Subdomains", str(subdomains)),
            ("Live hosts", str(live_hosts)),
            ("Unique IPs", str(ips)),
            ("Open ports", ports_label),
            ("Report", report_path),
        ]
        if extra_rows:
            rows.extend(extra_rows)
        path_keys = {
            "Report",
            "Inventory",
            "Changes",
            "Change MD",
            "Dashboard",
            "CSV",
            "Monitor",
            "Executive",
            "Platform",
            "Graph",
            "SLA",
            "Tickets",
        }
        for key, val in rows:
            print(f"  {key:<12} {self.green(val) if key not in path_keys else val}")
        print()
