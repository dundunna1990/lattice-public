"""Read-only Daily Care health checks."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _finding(code: str, severity: str, subject: str, detail: str) -> dict:
    return {"code": code, "severity": severity, "subject": subject, "detail": detail}


def _run(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def _network_wait_online_is_stale() -> bool:
    """True when the boot-time wait unit failed but networking is healthy now."""
    try:
        manager = _run(["/usr/bin/systemctl", "is-active", "NetworkManager.service"])
        if manager.returncode != 0 or manager.stdout.strip() != "active":
            return False
        state = _run(
            ["/usr/bin/nmcli", "-t", "-f", "STATE", "general"],
            timeout=7,
        )
        if state.returncode != 0:
            return False
        return state.stdout.strip().lower().startswith("connected")
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan_health(*, disk_warning_percent: int = 80, disk_critical_percent: int = 90) -> list[dict]:
    findings: list[dict] = []
    usage = shutil.disk_usage("/")
    used_pct = 100.0 * (usage.total - usage.free) / max(1, usage.total)
    if used_pct >= disk_critical_percent:
        findings.append(
            _finding("disk.root", "critical", "Root disk nearly full", f"{used_pct:.1f}% used")
        )
    elif used_pct >= disk_warning_percent:
        findings.append(
            _finding("disk.root", "attention", "Root disk getting full", f"{used_pct:.1f}% used")
        )

    stats = os.statvfs("/")
    if stats.f_files:
        inode_pct = 100.0 * (stats.f_files - stats.f_ffree) / stats.f_files
        if inode_pct >= 95:
            findings.append(
                _finding(
                    "disk.inodes",
                    "critical",
                    "Root filesystem inode pressure",
                    f"{inode_pct:.1f}% used",
                )
            )
        elif inode_pct >= 85:
            findings.append(
                _finding(
                    "disk.inodes",
                    "attention",
                    "Root filesystem inode pressure",
                    f"{inode_pct:.1f}% used",
                )
            )

    try:
        failed_result = _run(
            ["/usr/bin/systemctl", "--failed", "--no-legend", "--plain"]
        )
        if failed_result.returncode != 0:
            detail = (failed_result.stderr or failed_result.stdout or "systemctl check failed").strip()
            findings.append(
                _finding(
                    "systemd.check",
                    "attention",
                    "Could not inspect system services",
                    detail[:1000],
                )
            )
            failed = []
        else:
            failed = failed_result.stdout.splitlines()
        failed = [
            line.strip() for line in failed if line.strip() and "lattice-care.service" not in line
        ]
        if _network_wait_online_is_stale():
            failed = [
                line for line in failed if "NetworkManager-wait-online.service" not in line
            ]
        if failed:
            findings.append(
                _finding(
                    "systemd.failed",
                    "attention",
                    "Failed systemd unit(s)",
                    "; ".join(failed[:8])[:1000],
                )
            )
    except (OSError, subprocess.TimeoutExpired):
        findings.append(
            _finding(
                "systemd.check",
                "attention",
                "Could not inspect system services",
                "systemctl check failed",
            )
        )

    if Path("/var/run/reboot-required").exists():
        findings.append(
            _finding(
                "reboot.required",
                "attention",
                "Reboot required",
                "Installed updates require a reboot; Daily Care will never reboot automatically.",
            )
        )

    try:
        audit_result = _run(["/usr/bin/dpkg", "--audit"])
        audit = (audit_result.stdout or "").strip()
        if audit_result.returncode != 0:
            detail = (audit_result.stderr or audit or "dpkg audit failed").strip()
            findings.append(
                _finding(
                    "apt.dpkg",
                    "attention",
                    "Could not inspect package manager",
                    detail[:1000],
                )
            )
        elif audit:
            findings.append(
                _finding("apt.dpkg", "attention", "Package manager needs attention", audit[:1000])
            )
    except (OSError, subprocess.TimeoutExpired):
        findings.append(
            _finding(
                "apt.dpkg", "attention", "Could not inspect package manager", "dpkg audit failed"
            )
        )

    pressure = Path("/proc/pressure/memory")
    if pressure.exists():
        try:
            first = pressure.read_text().splitlines()[0]
            fields = dict(item.split("=", 1) for item in first.split()[1:] if "=" in item)
            avg10 = float(fields.get("avg10", "0"))
            if avg10 >= 30:
                findings.append(
                    _finding(
                        "memory.pressure",
                        "critical",
                        "Severe memory pressure",
                        f"PSI some avg10={avg10:.2f}%",
                    )
                )
            elif avg10 >= 10:
                findings.append(
                    _finding(
                        "memory.pressure",
                        "attention",
                        "Sustained memory pressure",
                        f"PSI some avg10={avg10:.2f}%",
                    )
                )
        except (OSError, ValueError, IndexError):
            pass

    hottest = None
    for temp_file in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            value = float(temp_file.read_text().strip()) / 1000.0
        except (OSError, ValueError):
            continue
        hottest = value if hottest is None else max(hottest, value)
    if hottest is not None and hottest >= 95:
        findings.append(
            _finding(
                "thermal.hot",
                "critical",
                "Critical temperature",
                f"Highest thermal zone {hottest:.1f} C",
            )
        )
    elif hottest is not None and hottest >= 85:
        findings.append(
            _finding(
                "thermal.hot",
                "attention",
                "High temperature",
                f"Highest thermal zone {hottest:.1f} C",
            )
        )
    return findings


def battery_should_defer(*, threshold_percent: int = 30) -> tuple[bool, str | None]:
    batteries = sorted(Path("/sys/class/power_supply").glob("BAT*"))
    if not batteries:
        return False, None
    levels = []
    discharging = False
    for battery in batteries:
        try:
            levels.append(int((battery / "capacity").read_text().strip()))
            status = (battery / "status").read_text().strip().lower()
            discharging = discharging or status == "discharging"
        except (OSError, ValueError):
            continue
    if levels and discharging and min(levels) < threshold_percent:
        return True, f"Battery {min(levels)}% and unplugged"
    return False, None
