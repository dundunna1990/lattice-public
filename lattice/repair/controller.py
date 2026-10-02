"""Structured, bounded manual repairs for the Lattice operator TUI.

This module deliberately exposes only Lattice-owned recovery operations.  It
never accepts an arbitrary command, service name, shell input, or SQL.
"""
from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from lattice.core.db import get_db_connection
from lattice.core.events import log_event
from lattice.healing.audit_log import AuditLog, DEFAULT_LOG_PATH


@dataclass(frozen=True)
class RepairCandidate:
    id: str
    category: str
    hostname: str
    worker_id: int | None
    problem: str
    action: str
    requires_confirmation: bool = True


@dataclass(frozen=True)
class RepairResult:
    candidate: RepairCandidate
    success: bool
    verified: bool
    summary: str
    error: str = ""


def _service_active(service: str) -> bool:
    try:
        return subprocess.run(
            ["systemctl", "is-active", "--quiet", service], timeout=10
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _worker_identity(hostname: str) -> tuple[int | None, str | None]:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, node_id FROM workers WHERE hostname=? AND removed_at IS NULL",
            (hostname,),
        ).fetchone()
        if row is None:
            return None, None
        return int(row[0]), str(row[1] or "") or None
    finally:
        conn.close()


def _mount_is_healthy(node_id: str) -> bool:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT state FROM mount_state WHERE peer_node_id=?", (node_id,)
        ).fetchone()
        return row is not None and str(row[0]) == "mounted"
    finally:
        conn.close()


def _shell_is_connected(node_id: str) -> bool:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT state FROM shell_connection_state WHERE peer_node_id=?", (node_id,)
        ).fetchone()
        return row is not None and str(row[0]) == "connected"
    finally:
        conn.close()


class RepairController:
    """Diagnose, preflight, audit, execute, and independently verify repairs."""

    def __init__(self, audit: AuditLog | None = None, sleeper: Callable[[float], None] = time.sleep):
        self.audit = audit or AuditLog(DEFAULT_LOG_PATH)
        self._sleep = sleeper

    def diagnose(self, status: Any) -> list[RepairCandidate]:
        candidates: list[RepairCandidate] = []
        master = str(getattr(status, "master_hostname", "Master"))
        if str(getattr(status, "daemon_status", "unknown")) != "running":
            candidates.append(RepairCandidate(
                "restart_master", "Lattice", master, None,
                "The Master daemon is not running.",
                "Restart the Lattice Master and verify its socket.",
            ))

        health = getattr(status, "health", {}) or {}
        network = health.get("network", {}) or {}
        if str(network.get("state")) == "degraded":
            candidates.append(RepairCandidate(
                "reconcile_network", "Network", master, None,
                str(network.get("label") or "Lattice network drift is detected."),
                "Run guarded Lattice network reconciliation.",
            ))

        access = {str(item.get("hostname")): item for item in health.get("node_access", [])}
        for worker in getattr(status, "workers", []) or []:
            hostname = str(worker.get("hostname") or "unknown")
            worker_id = worker.get("id")
            if not isinstance(worker_id, int):
                worker_id, _node_id = _worker_identity(hostname)
            state = str(worker.get("status") or "unknown").lower()
            node = access.get(hostname, {})
            if state in {"down", "degraded", "needs_attention"}:
                candidates.append(RepairCandidate(
                    "restart_worker", "Lattice", hostname, worker_id,
                    f"Worker state is {state.upper()}.",
                    "Restart the Lattice Worker and verify a fresh healthy instance.",
                ))
            if node and not bool(node.get("file_ok")):
                candidates.append(RepairCandidate(
                    "retry_mount", "File Access", hostname, worker_id,
                    f"File access is {node.get('file') or 'DOWN'}.",
                    "Retry managed file access and verify the mount.", False,
                ))
            if node and not bool(node.get("shell_ok")):
                candidates.append(RepairCandidate(
                    "reconcile_shell", "Trusted Shell", hostname, worker_id,
                    f"Trusted shell is {node.get('shell') or 'DOWN'}.",
                    "Reconnect the trusted shell and verify the pinned channel.", False,
                ))
        return candidates

    def candidates_for(self, status: Any, hostname: str | None = None) -> list[RepairCandidate]:
        candidates = self.diagnose(status)
        if hostname is None:
            return candidates
        return [item for item in candidates if item.hostname == hostname]


    def _audit(self, candidate: RepairCandidate, result: str, error: str = "") -> bool:
        return self.audit.log_entry(
            worker_id=candidate.worker_id,
            service=candidate.category,
            action=candidate.id,
            params={"hostname": candidate.hostname, "manual": True},
            result=result,
            error=error or None,
        )

    def _record(self, candidate: RepairCandidate, severity: str, message: str) -> None:
        log_event(candidate.worker_id, "repair.manual", severity, message, {
            "action": candidate.id, "hostname": candidate.hostname,
        })

    def _blocked(self, candidate: RepairCandidate, reason: str) -> RepairResult:
        self._audit(candidate, "blocked", reason)
        self._record(candidate, "warn", f"Manual repair blocked: {reason}")
        return RepairResult(candidate, False, False, "Repair blocked safely.", reason)

    def execute(self, candidate: RepairCandidate) -> RepairResult:
        """Execute one known action. Intent logging is mandatory and fail-closed."""
        if not self._audit(candidate, "manual_attempted"):
            return self._blocked(candidate, "The protected repair audit record is unavailable.")
        handlers = {
            "restart_master": self._restart_master,
            "restart_worker": self._restart_worker,
            "retry_mount": self._retry_mount,
            "restart_mount_manager": self._restart_mount_manager,
            "reconcile_shell": self._reconcile_shell,
            "restart_shell_manager": self._restart_shell_manager,
            "reconcile_network": self._reconcile_network,
        }
        handler = handlers.get(candidate.id)
        if handler is None:
            return self._blocked(candidate, "This is not a supported Lattice repair action.")
        try:
            result = handler(candidate)
        except Exception as exc:  # The TUI must report a real failure, not crash.
            result = RepairResult(candidate, False, False, "Repair attempted but failed.", str(exc))
        audit_result = "success" if result.success and result.verified else "failed"
        self._audit(candidate, audit_result, result.error)
        self._record(candidate, "info" if result.success else "error", result.summary)
        return result

    def _wait_for(self, predicate: Callable[[], bool], timeout: float = 20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            self._sleep(1)
        return predicate()


    def _restart_master(self, candidate: RepairCandidate) -> RepairResult:
        completed = subprocess.run(
            ["systemctl", "restart", "lattice-master.service"],
            capture_output=True, text=True, timeout=40,
        )
        if completed.returncode != 0:
            return RepairResult(candidate, False, False, "Master restart was refused.", (completed.stderr or completed.stdout).strip())
        def verified() -> bool:
            if not _service_active("lattice-master.service"):
                return False
            try:
                from lattice.core import self_check
                self_check.check_socket()
                return True
            except Exception:
                return False
        ok = self._wait_for(verified)
        return RepairResult(candidate, ok, ok,
            "Master restart verified." if ok else "Master restarted but its socket did not become healthy.")

    def _restart_worker(self, candidate: RepairCandidate) -> RepairResult:
        if candidate.worker_id is None:
            return self._blocked(candidate, "The Worker has no active Lattice identity.")
        from lattice.healing.engine import AutoHealEngine
        # Reuse the existing exact worker-only authenticated restart and its
        # independent instance-ID/health verification, without widening its API.
        ok = asyncio.run(AutoHealEngine()._attempt_heal_locked(
            candidate.worker_id, "lattice-worker", "restart", {"manual": True},
        ))
        return RepairResult(candidate, ok, ok,
            "Worker restart verified healthy." if ok else "Worker recovery could not be verified.")

    def _retry_mount(self, candidate: RepairCandidate) -> RepairResult:
        _worker_id, node_id = _worker_identity(candidate.hostname)
        if not node_id:
            return self._blocked(candidate, "The Worker has no immutable node identity for file access.")
        from lattice.cli.commands.mounts import _wake_manager
        from lattice.file_access.mount_manager import set_mount_preference
        set_mount_preference(node_id, "mounted")
        _wake_manager()
        ok = self._wait_for(lambda: _mount_is_healthy(node_id))
        return RepairResult(candidate, ok, ok,
            "Managed file access is mounted and verified." if ok else "Mount retry was requested but did not verify in time.")

    def _restart_mount_manager(self, candidate: RepairCandidate) -> RepairResult:
        completed = subprocess.run(["systemctl", "restart", "lattice-mount-manager.service"], capture_output=True, text=True, timeout=40)
        ok = completed.returncode == 0 and self._wait_for(lambda: _service_active("lattice-mount-manager.service"))
        return RepairResult(candidate, ok, ok,
            "Mount manager is active." if ok else "Mount manager did not become active.",
            "" if ok else (completed.stderr or completed.stdout).strip())


    def _reconcile_shell(self, candidate: RepairCandidate) -> RepairResult:
        _worker_id, node_id = _worker_identity(candidate.hostname)
        if not node_id:
            return self._blocked(candidate, "The Worker has no immutable node identity for trusted shell.")
        completed = subprocess.run(
            ["systemctl", "kill", "--kill-who=main", "--signal=SIGUSR1", "lattice-shell-connection-manager.service"],
            capture_output=True, text=True, timeout=10,
        )
        if completed.returncode != 0:
            return RepairResult(candidate, False, False, "Trusted-shell reconcile request was refused.", (completed.stderr or completed.stdout).strip())
        ok = self._wait_for(lambda: _shell_is_connected(node_id))
        return RepairResult(candidate, ok, ok,
            "Trusted shell is connected and verified." if ok else "Trusted-shell reconcile was requested but did not verify in time.")

    def _restart_shell_manager(self, candidate: RepairCandidate) -> RepairResult:
        completed = subprocess.run(["systemctl", "restart", "lattice-shell-connection-manager.service"], capture_output=True, text=True, timeout=40)
        ok = completed.returncode == 0 and self._wait_for(lambda: _service_active("lattice-shell-connection-manager.service"))
        return RepairResult(candidate, ok, ok,
            "Trusted-shell manager is active." if ok else "Trusted-shell manager did not become active.",
            "" if ok else (completed.stderr or completed.stdout).strip())

    def _reconcile_network(self, candidate: RepairCandidate) -> RepairResult:
        completed = subprocess.run(["systemctl", "start", "lattice-network-reconcile.service"], capture_output=True, text=True, timeout=60)
        if completed.returncode != 0:
            return RepairResult(candidate, False, False, "Guarded network repair was refused.", (completed.stderr or completed.stdout).strip())
        def verified() -> bool:
            from lattice.ip_change.reconcile import read_network_health
            health = read_network_health() or {}
            return str(health.get("state")) in {"healthy", "repaired"}
        ok = self._wait_for(verified, timeout=30)
        return RepairResult(candidate, ok, ok,
            "Network policy is verified." if ok else "Network reconciliation completed without a verified healthy policy state.")

    def history(self, limit: int = 20) -> list[dict[str, str]]:
        records: list[dict[str, str]] = []
        for entry in self.audit.read_entries(limit=limit):
            data = entry.get("data", {}) if isinstance(entry, dict) else {}
            if not isinstance(data, dict) or not data.get("manual"):
                continue
            records.append({
                "timestamp": str(entry.get("timestamp") or ""),
                "hostname": str((data.get("params") or {}).get("hostname") or "Master"),
                "action": str(data.get("action") or "repair"),
                "result": str(data.get("result") or "unknown"),
                "error": str(data.get("error") or ""),
            })
        return records[:limit]


    def autoheal_reasons(self, hostname: str) -> list[str]:
        """Plain-English reasons derived from actual configured policy/state."""
        worker_id, _node_id = _worker_identity(hostname)
        if worker_id is None:
            return ["This computer is not an active Lattice Worker."]
        from lattice.core.config import load_config
        from lattice.healing.engine import AutoHealEngine
        from lattice.healing.policy import MODE_AUTOMATIC, restart_budget_available
        from lattice.healing.signals import get_health_signals, get_worker_identity_status
        engine = AutoHealEngine()
        reasons: list[str] = []
        if engine._mode() != MODE_AUTOMATIC:
            reasons.append("Auto-Heal is in Alert Only mode, so it records problems but does not restart Workers.")
        if load_config().daemon.dry_run:
            reasons.append("Auto-Heal Dry Run is ON, so proposed repairs are recorded but not executed.")
        if not engine._get_opt_in_status(worker_id):
            reasons.append(f"Auto-Heal is OFF for {hostname}.")
        if engine._is_paused():
            reasons.append("Auto-Heal is temporarily paused by the owner.")
        if not get_worker_identity_status(worker_id):
            reasons.append("The Worker's identity is not verified, so Lattice will not restart it.")
        signals = get_health_signals(worker_id, "lattice-worker")
        failures = sum(signal.get("status") is False for signal in signals)
        if failures < 2:
            reasons.append(f"Only {failures} independent failure signal(s) exist; automatic restart requires 2.")
        if not restart_budget_available(worker_id, "lattice-worker"):
            reasons.append("The automatic two-restart safety limit in the last 15 minutes has been reached.")
        if not reasons:
            reasons.append("No Auto-Heal policy block is currently recorded. A fresh failure may still be required before automatic recovery starts.")
        return reasons


def manual_actions_for(status: Any, hostname: str | None = None) -> list[RepairCandidate]:
    """Return safe extra actions only for Lattice-owned local managers."""
    master = str(getattr(status, "master_hostname", "Master"))
    actions = RepairController().candidates_for(status, hostname)
    if hostname in {None, master}:
        if not _service_active("lattice-mount-manager.service"):
            actions.append(RepairCandidate("restart_mount_manager", "File Access", master, None, "The mount manager is stopped.", "Restart the Lattice mount manager and verify it is active."))
        if not _service_active("lattice-shell-connection-manager.service"):
            actions.append(RepairCandidate("restart_shell_manager", "Trusted Shell", master, None, "The trusted-shell manager is stopped.", "Restart the trusted-shell manager and verify it is active."))
    return actions
