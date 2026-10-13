"""One conservative Daily Care run on the local node."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import time
from collections.abc import Callable
from typing import TypeVar
from datetime import datetime, timezone
from pathlib import Path

from lattice.care.health import battery_should_defer, scan_health
from lattice.care.safety import (
    CareSafetyError,
    assert_allowed_delete,
    backup_work_active,
    care_run_lock,
)
from lattice.core.config import load_config
from lattice.core.db import get_db_connection, is_sqlite_busy_error

CRASH_ROOT = Path("/var/crash")
CRASH_MAX_AGE_SECONDS = 14 * 24 * 60 * 60
MAX_PATH_DELETE_BYTES = 2 * 1024**3
MAX_RUN_PATH_DELETE_BYTES = 4 * 1024**3
_DB_RETRY_DELAYS_SECONDS = (1.0, 2.0)
_T = TypeVar("_T")
_KERNEL_RE = re.compile(
    r"^linux-(?:image|image-unsigned|headers|modules|modules-extra|tools|cloud-tools)-[0-9].*$"
)


class CareRunError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(command: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CareRunError(f"Could not run {command[0]}: {exc}") from exc


def _db_write_with_retry(
    operation: str, callback: Callable[[sqlite3.Connection], _T]
) -> _T:
    """Run one Daily Care database write with bounded busy/locked retries."""
    attempts = len(_DB_RETRY_DELAYS_SECONDS) + 1
    for attempt in range(attempts):
        conn = get_db_connection()
        try:
            result = callback(conn)
            conn.commit()
            return result
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            if not is_sqlite_busy_error(exc):
                raise
            if attempt >= len(_DB_RETRY_DELAYS_SECONDS):
                raise CareRunError(
                    "Daily Care database remained busy while "
                    f"{operation} after {attempts} attempts"
                ) from exc
        finally:
            conn.close()
        time.sleep(_DB_RETRY_DELAYS_SECONDS[attempt])
    raise AssertionError("unreachable")


def _record_action(
    run_id: int, name: str, result: str, *, reclaimed: int = 0, detail: str | None = None
) -> None:
    def _write(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO care_actions"
            "(run_id,operation,result,bytes_reclaimed,detail) VALUES(?,?,?,?,?)",
            (run_id, name, result, max(0, int(reclaimed)), detail[:1000] if detail else None),
        )

    _db_write_with_retry(f"recording action {name}", _write)


def _care_plan(config, deferred_reason: str | None) -> list[str]:
    plan = ["health_scan"]
    if deferred_reason:
        plan.append(f"mutating_phase: deferred ({deferred_reason})")
        return plan
    for enabled, name in (
        (config.stale_crash_cleanup, "crash_age"),
        (config.apt_autoclean, "apt_autoclean"),
        (config.journal_vacuum, "journal_vacuum"),
        (config.flatpak_unused_cleanup, "flatpak_unused"),
        (config.old_kernel_cleanup, "old_kernels"),
        (config.security_updates, "security_updates"),
    ):
        if enabled:
            plan.append(name)
    return plan


def _replace_findings(run_id: int, findings: list[dict]) -> None:
    def _write(conn: sqlite3.Connection) -> None:
        conn.execute("UPDATE care_findings SET cleared_at=? WHERE cleared_at IS NULL", (_now(),))
        for item in findings:
            conn.execute(
                "INSERT INTO care_findings"
                "(run_id,severity,code,subject,detail,first_seen_at,last_seen_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    item["severity"],
                    item["code"],
                    item["subject"],
                    item["detail"],
                    _now(),
                    _now(),
                ),
            )

    _db_write_with_retry("recording health findings", _write)


def _cleanup_crash_reports(run_id: int) -> int:
    if not CRASH_ROOT.exists():
        _record_action(run_id, "crash_age", "skipped", detail="/var/crash is absent")
        return 0
    if CRASH_ROOT.is_symlink() or not CRASH_ROOT.is_dir():
        raise CareSafetyError("Daily Care refuses unsafe /var/crash")
    cutoff = time.time() - CRASH_MAX_AGE_SECONDS
    candidates: list[tuple[Path, int]] = []
    for path in CRASH_ROOT.iterdir():
        if not path.name.endswith(".crash"):
            continue
        try:
            meta = path.lstat()
        except OSError:
            continue
        if path.is_symlink() or not path.is_file() or meta.st_mtime >= cutoff:
            continue
        safe = assert_allowed_delete(path, allowed_parent=CRASH_ROOT.resolve(strict=False))
        candidates.append((safe, int(meta.st_size)))
    candidates = candidates[:100]
    planned = sum(size for _path, size in candidates)
    if planned > MAX_PATH_DELETE_BYTES:
        _record_action(
            run_id,
            "crash_age",
            "deferred",
            detail="Stale crash reports exceed the 2 GiB per-action safety cap",
        )
        return 0
    reclaimed = 0
    for path, size in candidates:
        path.unlink(missing_ok=True)
        reclaimed += size
    _record_action(
        run_id,
        "crash_age",
        "successful",
        reclaimed=reclaimed,
        detail=f"Removed {len(candidates)} stale .crash file(s)",
    )
    return reclaimed


def _apt_autoclean(run_id: int) -> None:
    result = _run(["/usr/bin/apt-get", "-y", "autoclean"])
    _record_action(
        run_id,
        "apt_autoclean",
        "successful" if result.returncode == 0 else "failed",
        detail=(result.stderr or result.stdout)[-1000:],
    )


def _journal_vacuum(run_id: int) -> None:
    result = _run(["/usr/bin/journalctl", "--vacuum-size=500M", "--vacuum-time=14d"], timeout=300)
    _record_action(
        run_id,
        "journal_vacuum",
        "successful" if result.returncode == 0 else "failed",
        detail=(result.stdout or result.stderr)[-1000:],
    )


def _flatpak_unused(run_id: int) -> None:
    if not Path("/usr/bin/flatpak").exists():
        _record_action(run_id, "flatpak_unused", "skipped", detail="Flatpak is not installed")
        return
    result = _run(["/usr/bin/flatpak", "uninstall", "--unused", "--noninteractive"], timeout=900)
    _record_action(
        run_id,
        "flatpak_unused",
        "successful" if result.returncode == 0 else "failed",
        detail=(result.stdout or result.stderr)[-1000:],
    )


def _kernel_cleanup(run_id: int) -> None:
    simulation = _run(["/usr/bin/apt-get", "-s", "autoremove"], timeout=120)
    if simulation.returncode != 0:
        _record_action(run_id, "old_kernels", "deferred", detail="APT autoremove simulation failed")
        return
    candidates = []
    for line in simulation.stdout.splitlines():
        if line.startswith("Remv "):
            parts = line.split()
            if len(parts) >= 2:
                candidates.append(parts[1])
    if not candidates:
        _record_action(run_id, "old_kernels", "skipped", detail="No autoremove candidates")
        return
    if any(not _KERNEL_RE.fullmatch(pkg) for pkg in candidates):
        _record_action(
            run_id,
            "old_kernels",
            "deferred",
            detail="Autoremove includes non-kernel packages; Daily Care refused it",
        )
        return
    installed = _run(
        ["/usr/bin/dpkg-query", "-W", "-f=${Package} ${db:Status-Abbrev}\\n", "linux-image-*"],
        timeout=60,
    )
    images = [
        parts[0]
        for line in installed.stdout.splitlines()
        if len(parts := line.split()) >= 2 and parts[1].startswith("ii")
    ]
    removing_images = {
        pkg for pkg in candidates if pkg.startswith(("linux-image-", "linux-image-unsigned-"))
    }
    if len(set(images) - removing_images) < 2:
        _record_action(
            run_id,
            "old_kernels",
            "deferred",
            detail="Kernel cleanup would leave fewer than two installed kernel images",
        )
        return
    verify = _run(["/usr/bin/apt-get", "-s", "remove", *candidates], timeout=120)
    proposed = {
        line.split()[1]
        for line in verify.stdout.splitlines()
        if line.startswith("Remv ") and len(line.split()) >= 2
    }
    if verify.returncode != 0 or proposed != set(candidates):
        _record_action(
            run_id,
            "old_kernels",
            "deferred",
            detail="Exact kernel removal simulation changed; Daily Care refused it",
        )
        return
    result = _run(["/usr/bin/apt-get", "-y", "remove", *candidates], timeout=1800)
    _record_action(
        run_id,
        "old_kernels",
        "successful" if result.returncode == 0 else "failed",
        detail=(result.stdout or result.stderr)[-1000:],
    )


def _unattended_policy_is_security_only() -> bool:
    """Validate the effective unattended-upgrades origin policy.

    APT merges every file under apt.conf.d, so inspecting only
    50unattended-upgrades can miss a later override. Fail closed unless every
    effective allowed origin is either the base release pocket or explicitly
    security/ESM scoped.
    """
    apt_config = Path("/usr/bin/apt-config")
    if not apt_config.exists():
        return False
    result = _run([str(apt_config), "dump"], timeout=60)
    if result.returncode != 0:
        return False

    allowed: list[str] = []
    for raw in result.stdout.splitlines():
        line = raw.strip()
        lowered = line.lower()
        if not (
            lowered.startswith("unattended-upgrade::allowed-origins")
            or lowered.startswith("unattended-upgrade::origins-pattern")
        ):
            continue
        if '"' not in line:
            continue
        try:
            value = line.split('"', 1)[1].rsplit('"', 1)[0].strip().lower()
        except IndexError:
            return False
        if value:
            allowed.append(value)

    if not allowed:
        return False

    base_release = {
        "${distro_id}:${distro_codename}",
        "origin=${distro_id},codename=${distro_codename}",
        "o=${distro_id},n=${distro_codename}",
    }
    for origin in allowed:
        if "security" in origin or "esm" in origin:
            continue
        if origin in base_release:
            continue
        return False
    return True

def _package_manager_is_healthy() -> tuple[bool, str | None]:
    """Return whether dpkg is in a safe state for automatic updates."""
    audit = _run(["/usr/bin/dpkg", "--audit"], timeout=60)
    if audit.returncode != 0:
        detail = (audit.stderr or audit.stdout or "dpkg --audit failed").strip()
        return False, detail[-1000:]
    detail = (audit.stdout or "").strip()
    if detail:
        return False, detail[-1000:]
    return True, None


def _security_updates(run_id: int) -> None:
    binary = Path("/usr/bin/unattended-upgrade")
    if not binary.exists():
        _record_action(
            run_id, "security_updates", "deferred", detail="unattended-upgrades is unavailable"
        )
        return
    healthy, package_detail = _package_manager_is_healthy()
    if not healthy:
        _record_action(
            run_id,
            "security_updates",
            "deferred",
            detail="Package manager is not healthy; automatic security updates were skipped. "
            + str(package_detail or ""),
        )
        return
    if not _unattended_policy_is_security_only():
        _record_action(
            run_id,
            "security_updates",
            "deferred",
            detail="Unattended-upgrades policy is not provably security-only",
        )
        return
    refresh = _run(["/usr/bin/apt-get", "update"], timeout=900)
    if refresh.returncode != 0:
        _record_action(
            run_id,
            "security_updates",
            "failed",
            detail="APT metadata refresh failed: " + (refresh.stderr or refresh.stdout)[-800:],
        )
        return
    result = _run([str(binary)], timeout=1800)
    _record_action(
        run_id,
        "security_updates",
        "successful" if result.returncode == 0 else "failed",
        detail=(result.stdout or result.stderr)[-1000:],
    )


@care_run_lock()
def run_daily_care(*, trigger: str = "scheduled") -> dict:
    if os.geteuid() != 0:
        raise CareRunError("Daily Care must run as root")
    if trigger not in {"scheduled", "manual"}:
        raise CareRunError("Daily Care trigger is invalid")
    started = _now()

    def _start_run(conn: sqlite3.Connection) -> int:
        cursor = conn.execute(
            "INSERT INTO care_runs(started_at,trigger,status) VALUES(?,?,'attention')",
            (started, trigger),
        )
        return int(cursor.lastrowid)

    run_id = _db_write_with_retry("starting the care run", _start_run)

    config = load_config().care
    if not config.enabled:
        def _mark_off(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE care_runs SET finished_at=?,status='off' WHERE id=?",
                (_now(), run_id),
            )

        _db_write_with_retry("marking Daily Care off", _mark_off)
        return {
            "run_id": run_id,
            "status": "off",
            "bytes_reclaimed": 0,
            "attention_count": 0,
            "critical_count": 0,
            "deferred_reason": None,
        }

    findings = scan_health(
        disk_warning_percent=config.disk_warning_percent,
        disk_critical_percent=config.disk_critical_percent,
    )
    defer_battery, battery_reason = battery_should_defer(
        threshold_percent=config.battery_defer_percent
    )
    defer_backup = backup_work_active()
    deferred_reason = (
        battery_reason
        if defer_battery
        else ("Backup/restore maintenance is active" if defer_backup else None)
    )
    plan = _care_plan(config, deferred_reason)

    def _record_plan(conn: sqlite3.Connection) -> None:
        conn.execute(
            "UPDATE care_runs SET plan_json=? WHERE id=?",
            (json.dumps(plan, sort_keys=False, separators=(",", ":")), run_id),
        )

    _db_write_with_retry("recording the care plan", _record_plan)
    reclaimed = 0
    if deferred_reason:
        _record_action(run_id, "mutating_phase", "deferred", detail=deferred_reason)
    else:
        if config.stale_crash_cleanup:
            reclaimed += _cleanup_crash_reports(run_id)
        if reclaimed <= MAX_RUN_PATH_DELETE_BYTES:
            if config.apt_autoclean:
                _apt_autoclean(run_id)
            if config.journal_vacuum:
                _journal_vacuum(run_id)
            if config.flatpak_unused_cleanup:
                _flatpak_unused(run_id)
            if config.old_kernel_cleanup:
                _kernel_cleanup(run_id)
            if config.security_updates:
                _security_updates(run_id)
        findings = scan_health(
            disk_warning_percent=config.disk_warning_percent,
            disk_critical_percent=config.disk_critical_percent,
        )

    conn = get_db_connection()
    try:
        failed_actions = conn.execute(
            "SELECT operation,detail FROM care_actions "
            "WHERE run_id=? AND result='failed' ORDER BY id",
            (run_id,),
        ).fetchall()
    finally:
        conn.close()
    for operation, detail in failed_actions:
        findings.append(
            {
                "severity": "attention",
                "code": f"care.action.{operation}",
                "subject": f"Daily Care action failed: {operation}",
                "detail": str(detail or "The maintenance action returned a failure result.")[:1000],
            }
        )

    critical = sum(1 for item in findings if item["severity"] == "critical")
    attention = sum(1 for item in findings if item["severity"] == "attention")
    status = (
        "critical" if critical else ("attention" if attention or deferred_reason else "healthy")
    )
    _replace_findings(run_id, findings)

    def _finish_run(conn: sqlite3.Connection) -> None:
        conn.execute(
            "UPDATE care_runs SET finished_at=?,status=?,bytes_reclaimed=?,"
            "attention_count=?,critical_count=?,deferred_reason=? WHERE id=?",
            (_now(), status, reclaimed, attention, critical, deferred_reason, run_id),
        )

    _db_write_with_retry("finishing the care run", _finish_run)
    return {
        "run_id": run_id,
        "status": status,
        "bytes_reclaimed": reclaimed,
        "attention_count": attention,
        "critical_count": critical,
        "deferred_reason": deferred_reason,
    }


def main() -> None:
    result = run_daily_care(trigger=os.environ.get("LATTICE_CARE_TRIGGER", "scheduled"))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
