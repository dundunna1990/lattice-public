"""Live, read-only verification for one Lattice node."""
from __future__ import annotations

import json
import os
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from lattice.care.health import scan_health
from lattice.care.observations import local_care_observation
from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.core.self_check import audit_log_capacity, check_db, check_socket
from lattice.file_access.identity import load_node_identity
from lattice.verification.backup import all_local_maintenance_failures_recovered


class VerificationError(RuntimeError):
    pass


def _run(command: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)


def _service_active(unit: str) -> bool:
    try:
        result = _run(["/usr/bin/systemctl", "is-active", "--quiet", unit])
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _failed_systemd_units() -> list[str]:
    try:
        result = _run(["/usr/bin/systemctl", "--failed", "--no-legend", "--plain"])
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VerificationError(f"could not inspect failed systemd units: {exc}") from exc
    if result.returncode not in {0, 1}:
        raise VerificationError("systemctl --failed did not return a usable result")
    units: list[str] = []
    for raw in result.stdout.splitlines():
        fields = raw.strip().lstrip("●").strip().split()
        if fields and "." in fields[0]:
            units.append(fields[0])
    return sorted(set(units))


def _network_state() -> str:
    try:
        from lattice.ip_change.reconcile import read_network_health
        health = read_network_health() or {}
        state = str(health.get("state") or "unknown")
        if state in {"healthy", "repaired"}:
            return "healthy"
        return state
    except Exception:
        return "unknown"


def _installed_not_live_media() -> bool:
    try:
        root = _run(["/usr/bin/findmnt", "-n", "-o", "SOURCE,FSTYPE", "/"])
        text = root.stdout.strip().lower()
        if root.returncode != 0 or any(token in text for token in ("overlay", "squashfs", "/dev/loop")):
            return False
        cdrom = _run(["/usr/bin/findmnt", "-n", "/cdrom"])
        return cdrom.returncode != 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _stale_unit_proof(unit: str, node_id: str) -> tuple[bool, str]:
    if unit == "lattice-backup-maintenance.service":
        ok, reasons = all_local_maintenance_failures_recovered(node_id)
        return ok, "; ".join(reasons) if reasons else "all backup maintenance failures are proven recovered"
    if unit == "NetworkManager-wait-online.service":
        ok = _service_active("NetworkManager.service") and _network_state() == "healthy"
        return ok, "NetworkManager and the current Lattice network are healthy" if ok else "network readiness is not proven healthy"
    if unit == "casper-md5check.service":
        ok = _installed_not_live_media()
        return ok, "host is an installed system, not a live-media boot" if ok else "live-media state could not be ruled out"
    return False, "no safe stale-failure verifier is registered for this unit"


def _master_core_blockers() -> tuple[list[str], dict]:
    blockers: list[str] = []
    evidence: dict = {}
    from lattice.cli.tui import get_status

    status = get_status()
    evidence["daemon_status"] = status.daemon_status
    if status.daemon_status != "running":
        blockers.append(f"Master daemon is {status.daemon_status}")
    for key in ("network", "file", "shell"):
        item = dict(status.health.get(key) or {})
        evidence[key] = item
        if str(item.get("state") or "unknown") not in {"healthy", "idle"}:
            blockers.append(f"Master {key} state is {item.get('state') or 'unknown'}")
    backups = list(status.health.get("backup_nodes") or [])
    evidence["backup_nodes"] = backups
    bad_backups = [str(item.get("hostname") or "unknown") for item in backups if not bool(item.get("ok"))]
    if bad_backups:
        blockers.append("Backup protection is not healthy for: " + ", ".join(bad_backups))
    automation = dict(status.health.get("automation") or {})
    evidence["automation"] = automation
    if str(automation.get("breaker_state") or "healthy") == "degraded":
        blockers.append("Lattice auto-heal circuit breaker is degraded")
    try:
        check_db()
        evidence["db"] = "healthy"
    except Exception as exc:
        evidence["db"] = str(exc)
        blockers.append(f"Master database self-check failed: {exc}")
    try:
        check_socket()
        evidence["socket"] = "healthy"
    except Exception as exc:
        evidence["socket"] = str(exc)
        blockers.append(f"Master control socket self-check failed: {exc}")
    size, severity = audit_log_capacity()
    evidence["audit_log_bytes"] = size
    if severity is not None:
        blockers.append(f"Master audit log requires attention ({size} bytes)")
    return blockers, evidence


def _worker_core_blockers() -> tuple[list[str], dict]:
    from lattice.worker.health import HealthChecker

    snapshot = HealthChecker().current_snapshot()
    blockers: list[str] = []
    if snapshot.get("status") != "healthy":
        bad = [
            str(item.get("name") or "unknown")
            for item in snapshot.get("services", [])
            if str(item.get("status") or "") not in {"healthy", "active", "running", "ok"}
        ]
        blockers.append("Worker live health is degraded" + (": " + ", ".join(bad) if bad else ""))
    return blockers, snapshot


def _role() -> str:
    try:
        value = Path("/etc/lattice/role").read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    if value not in {"master", "worker"}:
        raise VerificationError("local Lattice role is unavailable")
    return value


def collect_local_verification(role: str | None = None) -> dict:
    """Collect current node evidence without changing machine state."""
    role = role or _role()
    identity = load_node_identity()
    if identity is None:
        raise VerificationError("local Lattice node identity is unavailable")
    config = load_config()
    blockers, core = (
        _master_core_blockers() if role == "master" else _worker_core_blockers()
    )
    findings = scan_health(
        disk_warning_percent=config.care.disk_warning_percent,
        disk_critical_percent=config.care.disk_critical_percent,
    )
    for item in findings:
        if item.get("code") != "systemd.failed":
            blockers.append(f"{item.get('subject')}: {item.get('detail')}")

    try:
        failed_units = _failed_systemd_units()
    except VerificationError as exc:
        failed_units = []
        blockers.append(str(exc))
    failed_units = [unit for unit in failed_units if unit != "lattice-care.service"]
    stale_units: list[dict] = []
    blocking_units: list[dict] = []
    for unit in failed_units:
        ok, reason = _stale_unit_proof(unit, identity.node_id)
        item = {"unit": unit, "reason": reason}
        if ok:
            stale_units.append(item)
        else:
            blocking_units.append(item)
            blockers.append(f"Failed systemd unit {unit}: {reason}")

    stored_care = local_care_observation(node_id=identity.node_id)
    return {
        "node_id": identity.node_id,
        "hostname": socket.gethostname(),
        "role": role,
        "status": "healthy" if not blockers else "blocked",
        "blockers": blockers,
        "stale_failed_units": stale_units,
        "blocking_failed_units": blocking_units,
        "network_state": _network_state(),
        "core": core,
        "live_care_findings": findings,
        "stored_care": stored_care,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _record_clean_care_snapshot() -> int:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "UPDATE care_findings SET cleared_at=? WHERE cleared_at IS NULL",
            (now,),
        )
        cursor = conn.execute(
            """INSERT INTO care_runs(
                   started_at,finished_at,trigger,status,bytes_reclaimed,
                   attention_count,critical_count,deferred_reason,plan_json)
               VALUES(?,?,'manual','healthy',0,0,0,NULL,?)""",
            (now, now, json.dumps(["health_scan", "verification_only"])),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()


def clear_local_resolved_state(role: str | None = None) -> dict:
    """Reset only stale failed-unit flags after fresh local verification."""
    if os.geteuid() != 0:
        raise VerificationError("local resolved-state clearing must run as root")
    before = collect_local_verification(role)
    if before["status"] != "healthy":
        raise VerificationError("local verification is blocked: " + "; ".join(before["blockers"][:6]))

    reset: list[str] = []
    for item in before["stale_failed_units"]:
        unit = str(item["unit"])
        result = _run(["/usr/bin/systemctl", "reset-failed", unit])
        if result.returncode != 0:
            raise VerificationError(f"could not reset stale failed state for {unit}")
        reset.append(unit)

    after = collect_local_verification(role)
    if after["status"] != "healthy" or after["stale_failed_units"]:
        raise VerificationError("local state changed during clear; verification must be run again")
    care_findings = [
        item for item in after["live_care_findings"]
        if item.get("code") != "systemd.failed"
    ]
    if care_findings:
        raise VerificationError("live Daily Care findings remain after clear")
    run_id = _record_clean_care_snapshot()
    return {
        "status": "cleared",
        "hostname": after["hostname"],
        "reset_units": reset,
        "care_run_id": run_id,
    }
