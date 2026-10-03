import socket
import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

def _get_input(stdscr, prompt: str, y: int, x: int) -> str:
    """Get a string input with resize handling."""
    curses.curs_set(1)
    input_str = ""
    while True:
        stdscr.addstr(y, x, prompt + input_str + " ")
        stdscr.refresh()
        key = stdscr.getch()
        if key == ord('\n') or key == ord('\r'):
            break
        elif key == curses.KEY_BACKSPACE or key == 127:
            input_str = input_str[:-1]
        elif key == curses.KEY_RESIZE:
            # Redraw the screen
            stdscr.clear()
            stdscr.refresh()
            # Re-display prompt and current input
        elif 32 <= key <= 126:
            input_str += chr(key)
        # Redraw prompt with current input
    curses.curs_set(0)
    return input_str

import socket



import curses
import textwrap
import textwrap
import os
import subprocess
import sys
from typing import List, Dict, Any, Optional
from pathlib import Path
from lattice.core.db import get_db_connection
from lattice.core.service_status import (
    HEALTHY_SERVICE_STATUS_SQL,
    FAILED_SERVICE_STATUS_SQL,
)
from lattice.core.config import load_config, save_config, LatticeConfig
from lattice.core.events import get_active_alerts
from lattice.master.state_machine import get_worker_state
from lattice.core.daemon import reload_daemon
# ---- Data structure ----
class LatticeStatus:
    def __init__(self, role: str, master_hostname: str, master_ip: str,
                 daemon_status: str, uptime: str, version: str,
                 workers: List[Dict[str, Any]], alerts: List[Dict[str, Any]],
                 health: Optional[Dict[str, Any]] = None,
                 events: Optional[List[Dict[str, Any]]] = None,
                 problems: Optional[List[Dict[str, Any]]] = None):
        self.role = role
        self.master_hostname = master_hostname
        self.master_ip = master_ip
        self.daemon_status = daemon_status
        self.uptime = uptime
        self.version = version
        self.workers = workers
        self.alerts = alerts
        self.health = health or {}
        self.events = events or []
        self.problems = problems or []


def _service_active(service: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            timeout=5,
        )
        return "running" if result.returncode == 0 else "stopped"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def _network_health() -> Dict[str, Any]:
    try:
        from lattice.ip_change.reconcile import read_network_health
        reconcile_health = read_network_health()
        if reconcile_health is not None:
            state = reconcile_health.get("state")
            expected = reconcile_health.get("expected") or "unknown"
            actual = reconcile_health.get("actual") or "no address"
            if state in {"healthy", "repaired"}:
                label = f"Stable ({expected})" if state == "healthy" else f"Auto-repaired ({expected})"
                return {"state": "healthy", "label": label}
            labels = {
                "drift_pending": f"Drift: {actual} / expected {expected}; auto-repair pending",
                "repair_cooldown": f"Drift: {actual} / expected {expected}; repair cooldown",
                "unsafe_network": "Auto-repair blocked: untrusted or unsafe network",
                "repair_failed": "Auto-repair failed safely; previous network restored",
            }
            return {"state": "degraded", "label": labels.get(state, f"Network: {state or 'unknown'}")}

        from lattice.ip_change.state import read_expected_network
        from lattice.ip_change.monitor import get_actual_ip
        expected = read_expected_network()
        if not expected:
            return {"state": "unknown", "label": "Not configured"}
        interface = str(expected.get("interface") or "")
        expected_ip = str(expected.get("address") or "")
        if not interface or not expected_ip:
            return {"state": "unknown", "label": "State incomplete"}
        actual_ip = get_actual_ip(interface)
        if actual_ip == expected_ip:
            return {"state": "healthy", "label": f"Stable ({actual_ip})"}
        return {"state": "degraded", "label": f"Drift: {actual_ip or 'no address'} / expected {expected_ip}"}
    except Exception as exc:
        logger.debug("Could not read network health for TUI: %s", exc)
        return {"state": "unknown", "label": "Unavailable"}


def _transport_health(conn, worker_count: int) -> tuple[Dict[str, Any], Dict[str, Any]]:
    if worker_count == 0:
        idle = {"state": "idle", "ok": 0, "total": 0, "label": "No peers yet"}
        return dict(idle), dict(idle)

    mount_rows = conn.execute(
        "SELECT state, COUNT(*) FROM mount_state GROUP BY state"
    ).fetchall()
    mount_counts = {str(row[0]): int(row[1]) for row in mount_rows}
    mounted = mount_counts.get("mounted", 0)
    mount_problem = sum(
        count for state, count in mount_counts.items()
        if state in {"offline", "stale", "mount_problem"}
    )
    if mount_problem:
        file_health = {
            "state": "degraded", "ok": mounted, "total": worker_count,
            "label": f"{mounted}/{worker_count} mounted",
        }
    elif mounted >= worker_count:
        file_health = {
            "state": "healthy", "ok": worker_count, "total": worker_count,
            "label": f"{worker_count}/{worker_count} available",
        }
    else:
        file_health = {
            "state": "unknown", "ok": mounted, "total": worker_count,
            "label": f"{mounted}/{worker_count} known",
        }

    shell_rows = conn.execute(
        "SELECT state, COUNT(*) FROM shell_connection_state GROUP BY state"
    ).fetchall()
    shell_counts = {str(row[0]): int(row[1]) for row in shell_rows}
    connected = shell_counts.get("connected", 0)
    unavailable = shell_counts.get("unavailable", 0)
    if unavailable:
        shell_health = {
            "state": "degraded", "ok": connected, "total": worker_count,
            "label": f"{connected}/{worker_count} connected",
        }
    elif connected >= worker_count:
        shell_health = {
            "state": "healthy", "ok": worker_count, "total": worker_count,
            "label": f"{worker_count}/{worker_count} connected",
        }
    else:
        shell_health = {
            "state": "unknown", "ok": connected, "total": worker_count,
            "label": f"{connected}/{worker_count} known",
        }
    return file_health, shell_health


def _backup_node_statuses(conn, master_hostname: str, workers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return one concise end-to-end Backup state per visible computer."""
    hostnames = [master_hostname] + [
        str(worker.get("hostname") or "unknown") for worker in workers
    ]
    rows = conn.execute(
        """SELECT fn.hostname, bj.enabled, bj.paused, bjo.state,
                  bjo.last_result, bjo.last_success_at, bjo.failure_streak,
                  bjo.credential_missing, bjo.last_reported_at,
                  bt.enabled, bto.present, bto.health, bto.last_reported_at
           FROM fleet_nodes fn
           LEFT JOIN backup_jobs bj ON bj.source_node_id=fn.node_id
           LEFT JOIN backup_job_observations bjo ON bjo.job_id=bj.id
           LEFT JOIN backup_targets bt ON bt.id=bj.target_id
           LEFT JOIN backup_target_observations bto ON bto.target_id=bt.id
           WHERE fn.hostname IN ({})
           ORDER BY fn.hostname COLLATE NOCASE, bj.id""".format(
               ",".join("?" for _ in hostnames)
           ),
        tuple(hostnames),
    ).fetchall()

    grouped: Dict[str, List[Any]] = {hostname: [] for hostname in hostnames}
    for row in rows:
        grouped.setdefault(str(row[0]), []).append(row)

    def stale_timestamp(value: object, now: datetime) -> bool:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            age = (now - parsed.astimezone(timezone.utc)).total_seconds()
            return age < -60 or age > 60
        except (TypeError, ValueError):
            return True

    result: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for hostname in hostnames:
        jobs = [row for row in grouped.get(hostname, []) if row[1] is not None]
        if not jobs:
            result.append({"hostname": hostname, "state": "not_set_up", "label": "NOT SET UP", "ok": False})
            continue

        enabled = [row for row in jobs if bool(row[1])]
        if not enabled:
            result.append({"hostname": hostname, "state": "off", "label": "OFF", "ok": False})
            continue
        if any(not bool(row[9]) for row in enabled):
            result.append({"hostname": hostname, "state": "off", "label": "OFF", "ok": False})
            continue
        if any(bool(row[2]) for row in enabled):
            result.append({"hostname": hostname, "state": "paused", "label": "PAUSED", "ok": False})
            continue

        states = [str(row[3] or "unknown") for row in enabled]
        observation_stale = any(
            stale_timestamp(row[8], now) for row in enabled
            if hostname != master_hostname
        )
        target_stale = any(stale_timestamp(row[12], now) for row in enabled)
        target_problem = any(
            row[10] is not None and (
                not bool(row[10]) or str(row[11] or "unknown") not in {"healthy", "ok"}
            )
            for row in enabled
        )

        if observation_stale or target_stale:
            state, label, ok = "unknown", "UNKNOWN", False
        elif target_problem:
            state, label, ok = "degraded", "DEGRADED", False
        elif any(
            bool(row[7]) or int(row[6] or 0) > 0 or job_state == "pending"
            for row, job_state in zip(enabled, states)
        ):
            state, label, ok = "degraded", "DEGRADED", False
        elif any(job_state == "running" for job_state in states):
            state, label, ok = "running", "RUNNING", True
        elif all(job_state == "healthy" and row[5] for row, job_state in zip(enabled, states)):
            state, label, ok = "healthy", "HEALTHY", True
        elif any(job_state == "never_backed_up" for job_state in states):
            state, label, ok = "ready", "READY", True
        else:
            state, label, ok = "unknown", "UNKNOWN", False

        result.append({"hostname": hostname, "state": state, "label": label, "ok": ok})
    return result


def _care_node_statuses(conn, master_hostname: str, workers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return Daily Care status for the local Master and replicated Workers."""
    from lattice.care.observations import local_care_observation, observation_is_stale

    local = local_care_observation()
    result = [dict(local)]
    worker_names = {
        str(worker.get("hostname") or "unknown") for worker in workers
    }
    rows = conn.execute(
        """SELECT node_id,hostname,status,last_run_at,bytes_reclaimed,
                  attention_count,critical_count,deferred_reason,findings_json,last_reported_at
           FROM care_observations
           ORDER BY hostname COLLATE NOCASE"""
    ).fetchall()
    for row in rows:
        item = dict(row)
        if item["hostname"] not in worker_names:
            continue
        try:
            item["findings"] = json.loads(item.pop("findings_json") or "[]")
        except (TypeError, json.JSONDecodeError):
            item["findings"] = []
        if observation_is_stale(item.get("last_run_at")):
            item["reported_status"] = item.get("status")
            item["status"] = "stale"
        result.append(item)

    existing = {str(item.get("hostname")) for item in result}
    for hostname in sorted(worker_names - existing):
        result.append({
            "hostname": hostname,
            "status": "stale",
            "last_run_at": None,
            "bytes_reclaimed": 0,
            "attention_count": 0,
            "critical_count": 0,
            "deferred_reason": None,
            "findings": [],
        })
    return result


def _node_access_status(
    conn,
    master_hostname: str,
    daemon_status: str,
    workers: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build per-node File/Shell/Admin state from persisted Lattice evidence."""
    try:
        row = conn.execute("SELECT generation FROM fleet_state WHERE id = 1").fetchone()
        generation = int(row[0]) if row is not None else 0
        node_rows = conn.execute(
            """SELECT node_id, hostname, role, file_transport_generation,
                      shell_transport_generation
               FROM fleet_nodes
               WHERE membership_state = 'active'"""
        ).fetchall()
    except Exception as exc:
        logger.debug("Could not read fleet transport state for TUI: %s", exc)
        generation = 0
        node_rows = []

    nodes = {str(row[1]): row for row in node_rows}
    try:
        mount_rows = conn.execute("SELECT peer_node_id, state FROM mount_state").fetchall()
        mounts = {str(row[0]): str(row[1]) for row in mount_rows}
    except Exception:
        mounts = {}
    try:
        shell_rows = conn.execute(
            "SELECT peer_node_id, state FROM shell_connection_state"
        ).fetchall()
        shells = {str(row[0]): str(row[1]) for row in shell_rows}
    except Exception:
        shells = {}
    try:
        export_rows = conn.execute(
            """SELECT w.hostname, s.status, s.last_reported_at
               FROM services s
               JOIN workers w ON w.id = s.worker_id
               WHERE s.name = 'file_export'
                 AND w.removed_at IS NULL"""
        ).fetchall()
        exports = {
            str(row[0]): (str(row[1]), str(row[2] or ""))
            for row in export_rows
        }
    except Exception:
        exports = {}

    def applied(value: object) -> bool:
        try:
            return generation > 0 and int(value or 0) == generation
        except (TypeError, ValueError):
            return False

    def export_healthy(hostname: str) -> bool:
        status_row = exports.get(hostname)
        if status_row is None or status_row[0] != "healthy":
            return False
        try:
            reported = datetime.fromisoformat(status_row[1])
            if reported.tzinfo is None:
                reported = reported.replace(tzinfo=timezone.utc)
            reported = reported.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return False
        return datetime.now(timezone.utc) - reported < timedelta(seconds=30)

    result: List[Dict[str, Any]] = []
    master = nodes.get(master_hostname)
    try:
        from lattice.file_access.identity import load_node_identity
        from lattice.file_access.home_export import home_bind_is_current
        local_identity = load_node_identity()
        local_export_ok = bool(
            local_identity is not None and home_bind_is_current(local_identity)
        )
    except Exception:
        local_export_ok = False
    master_file = bool(
        master is not None and applied(master[3]) and local_export_ok
    )
    master_shell = bool(master is not None and applied(master[4]) and daemon_status == "running")
    result.append({
        "hostname": master_hostname,
        "role": "master",
        "file": "READY" if master_file else "NOT READY",
        "file_ok": master_file,
        "shell": "READY" if master_shell else "NOT READY",
        "shell_ok": master_shell,
        "admin": "READY" if master_shell else "NOT READY",
        "admin_ok": master_shell,
    })

    for worker in workers:
        hostname = str(worker.get("hostname") or "unknown")
        node = nodes.get(hostname)
        node_id = str(node[0]) if node is not None else ""
        mount_state = mounts.get(node_id, "unknown")
        shell_state = shells.get(node_id, "unknown")
        export_ok = export_healthy(hostname)
        file_ok = mount_state == "mounted" and export_ok
        shell_ok = shell_state == "connected"
        admin_ok = bool(node is not None and shell_ok and applied(node[4]))
        result.append({
            "hostname": hostname,
            "role": "worker",
            "file": "CONNECTED" if file_ok else ("PAUSED" if mount_state == "paused" else "DOWN"),
            "file_ok": file_ok,
            "shell": "CONNECTED" if shell_ok else "DOWN",
            "shell_ok": shell_ok,
            "admin": "READY" if admin_ok else "NOT READY",
            "admin_ok": admin_ok,
        })
    return result


def _fleet_health(daemon_status: str, workers: List[Dict[str, Any]],
                  alerts: List[Dict[str, Any]], network: Dict[str, Any],
                  file_health: Dict[str, Any], shell_health: Dict[str, Any]) -> Dict[str, Any]:
    problems = 0
    if daemon_status != "running":
        problems += 1
    problems += sum(
        1 for worker in workers
        if worker["status"] in {"degraded", "down", "configuring", "needs_attention"}
    )
    problems += len(alerts)
    if network.get("state") == "degraded":
        problems += 1
    if file_health.get("state") == "degraded":
        problems += 1
    if shell_health.get("state") == "degraded":
        problems += 1
    online = sum(1 for worker in workers if worker["status"] not in {"down", "disabled"})
    return {
        "state": "healthy" if problems == 0 else "degraded",
        "problems": problems,
        "online": online,
        "nodes": 1 + len(workers),
    }


def _problem_outcome(cursor, event_id: int, worker_id: Optional[int], event_type: str) -> str:
    """Summarize only a problem outcome that Lattice can prove from persisted state."""
    alert = cursor.execute(
        """
        SELECT a.resolved_at, r.type, r.details
        FROM alerts a
        LEFT JOIN events r ON r.id = a.resolution_event_id
        WHERE a.trigger_event_id = ?
        ORDER BY a.id DESC LIMIT 1
        """,
        (event_id,),
    ).fetchone()
    if alert is not None:
        resolved_at, resolution_type, resolution_details = alert
        if resolved_at:
            if resolution_type == "network.reconcile_recovered":
                try:
                    details = json.loads(resolution_details or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    details = {}
                return "REPAIRED" if details.get("state") == "repaired" else "RECOVERED"
            if resolution_type == "autoheal.success":
                return "RESTARTED"
            return "RECOVERED"
        if event_type == "autoheal.protected_issue":
            return "NO CHANGE"
        if event_type == "autoheal.detected":
            return "ALERTED"
        return "ATTENTION"

    if worker_id is not None:
        autoheal = cursor.execute(
            """
            SELECT id FROM events
            WHERE worker_id = ? AND id > ? AND type = 'autoheal.success'
            ORDER BY id LIMIT 1
            """,
            (worker_id, event_id),
        ).fetchone()
        healthy = cursor.execute(
            """
            SELECT id FROM events
            WHERE worker_id = ? AND id > ?
              AND (type = 'health_check' OR type LIKE 'health_check.%')
              AND LOWER(severity) IN ('ok', 'info', 'success')
            ORDER BY id LIMIT 1
            """,
            (worker_id, event_id),
        ).fetchone()
        if autoheal is not None and (healthy is None or autoheal[0] <= healthy[0]):
            return "RESTARTED"
        if healthy is not None:
            return "RECOVERED"

        if event_type in {"autoheal.detected", "autoheal.failed", "autoheal.protected_issue"}:
            recovered = cursor.execute(
                """
                SELECT 1 FROM events
                WHERE worker_id = ? AND id > ? AND type = 'recovery.verified'
                ORDER BY id LIMIT 1
                """,
                (worker_id, event_id),
            ).fetchone()
            if recovered is not None:
                return "RECOVERED"

        if event_type == "network.reconcile_failed":
            recovered = cursor.execute(
                """
                SELECT details FROM events
                WHERE worker_id = ? AND id > ? AND type = 'network.reconcile_recovered'
                ORDER BY id LIMIT 1
                """,
                (worker_id, event_id),
            ).fetchone()
            if recovered is not None:
                try:
                    details = json.loads(recovered[0] or "{}")
                except (TypeError, ValueError, json.JSONDecodeError):
                    details = {}
                return "REPAIRED" if details.get("state") == "repaired" else "RECOVERED"

    if event_type == "autoheal.master_detected":
        recovered = cursor.execute(
            "SELECT 1 FROM events WHERE id > ? AND type = 'autoheal.master_recovered' ORDER BY id LIMIT 1",
            (event_id,),
        ).fetchone()
        if recovered is not None:
            return "RECOVERED"

    return {
        "autoheal.protected_issue": "NO CHANGE",
        "autoheal.detected": "ALERTED",
        "autoheal.hard_no": "BLOCKED",
        "autoheal.audit_failed": "STOPPED",
        "autoheal.not_found": "FAILED",
        "autoheal.failed": "FAILED",
        "network.reconcile_failed": "ATTENTION",
    }.get(event_type, "OPEN")


def _automation_summary(conn, config: LatticeConfig) -> Dict[str, Any]:
    """Build the full-dashboard automation snapshot from existing Lattice state."""
    mode_row = conn.execute(
        "SELECT value FROM config WHERE key = 'autoheal.mode'"
    ).fetchone()
    mode = "automatic" if mode_row and mode_row[0] == "automatic" else "alert_only"

    breaker_rows = conn.execute(
        "SELECT state, COUNT(*) FROM circuit_breaker_state GROUP BY state"
    ).fetchall()
    breaker_counts = {str(row[0]): int(row[1]) for row in breaker_rows}
    open_count = breaker_counts.get("open", 0)
    half_open_count = breaker_counts.get("half_open", 0)
    unexpected_count = sum(
        count for state, count in breaker_counts.items()
        if state not in {"closed", "open", "half_open"}
    )
    if open_count:
        breaker_label = f"{open_count} OPEN"
        breaker_state = "degraded"
    elif half_open_count:
        breaker_label = f"{half_open_count} HALF-OPEN"
        breaker_state = "warning"
    elif unexpected_count:
        breaker_label = "CHECK"
        breaker_state = "warning"
    else:
        breaker_label = "CLOSED"
        breaker_state = "healthy"

    last_fix = None
    fix_rows = conn.execute(
        """
        SELECT timestamp, type, details
        FROM events
        WHERE type IN ('autoheal.success', 'network.reconcile_recovered')
        ORDER BY id DESC
        LIMIT 20
        """
    ).fetchall()
    for timestamp, event_type, details_json in fix_rows:
        if event_type == "autoheal.success":
            last_fix = timestamp
            break
        try:
            details = json.loads(details_json or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            details = {}
        if event_type == "network.reconcile_recovered" and details.get("state") == "repaired":
            last_fix = timestamp
            break

    return {
        "mode": mode,
        "dry_run": bool(config.daemon.dry_run),
        "breaker_label": breaker_label,
        "breaker_state": breaker_state,
        "last_fix": last_fix,
    }


def _dashboard_event_history(cursor, *, problems_only: bool = False, limit: int = 5) -> List[Dict[str, Any]]:
    """Return persisted dashboard events, optionally restricted to problem severity."""
    where = (
        "WHERE LOWER(e.severity) IN ('warn', 'warning', 'error', 'critical')"
        if problems_only else ""
    )
    cursor.execute(
        f"""
            SELECT e.id, e.timestamp, e.worker_id, e.type, e.severity, e.message, w.hostname
            FROM events e
            LEFT JOIN workers w ON w.id = e.worker_id
            {where}
            ORDER BY e.id DESC LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    result = []
    for row in rows:
        event = {
            "timestamp": row[1],
            "severity": row[4],
            "message": row[5],
            "worker": row[6] or "Master",
        }
        if problems_only:
            event["outcome"] = _problem_outcome(cursor, int(row[0]), row[2], str(row[3]))
        result.append(event)
    return result


# ---- Fetch real status ----

def _worker_status() -> LatticeStatus:
    """Build a Worker-local dashboard snapshot without Master-only assumptions."""
    from lattice.worker.health import HealthChecker
    from lattice.onboarding import get_worker_master_endpoint
    from lattice.file_access.identity import load_node_identity
    from lattice.backup.observations import (
        local_backup_observations,
        local_backup_target_observations,
    )
    from lattice.care.observations import local_care_observation

    identity = load_node_identity()
    endpoint = get_worker_master_endpoint() or {}
    snapshot = HealthChecker().current_snapshot()
    hostname = socket.gethostname()
    node_id = identity.node_id if identity is not None else None

    conn = get_db_connection()
    try:
        peer_names = {
            str(row["node_id"]): str(row["hostname"])
            for row in conn.execute(
                """SELECT node_id,hostname FROM fleet_nodes
                   WHERE membership_state='active' ORDER BY hostname COLLATE NOCASE"""
            ).fetchall()
        }

        mounts = []
        for row in snapshot.get("mount_observations", []):
            peer_id = str(row.get("peer_node_id") or "")
            if not peer_id or peer_id == node_id:
                continue
            mounts.append({
                **dict(row),
                "hostname": peer_names.get(peer_id, peer_id[:12] or "unknown"),
            })

        shell_connections = []
        for row in conn.execute(
            """SELECT peer_node_id,hostname,state,selected_ip,failure_count
               FROM shell_connection_state
               WHERE state!='retired'
               ORDER BY hostname,peer_node_id LIMIT 64"""
        ).fetchall():
            item = dict(row)
            if item.get("peer_node_id") == node_id:
                continue
            peer_id = str(item.get("peer_node_id") or "")
            raw_name = str(item.get("hostname") or "")
            item["hostname"] = peer_names.get(
                peer_id,
                raw_name if raw_name and raw_name != peer_id else peer_id[:12],
            )
            shell_connections.append(item)

        backup_observations = local_backup_observations()
        backup_by_uuid = {
            str(item.get("job_uuid")): dict(item)
            for item in backup_observations
            if item.get("job_uuid")
        }
        backup_jobs = []
        for row in conn.execute(
            """SELECT bj.job_uuid,bj.enabled,bj.paused,bj.source_path,
                      bt.friendly_name,bt.target_type,bt.host_node_id
               FROM backup_jobs bj
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.source_node_id=?
               ORDER BY bj.id""",
            (node_id,),
        ).fetchall():
            item = dict(row)
            item["observation"] = backup_by_uuid.get(str(item["job_uuid"]), {})
            backup_jobs.append(item)

        hosted_targets = [
            dict(item) for item in local_backup_target_observations()
        ]
        target_meta = {
            str(row["target_uuid"]): {
                "friendly_name": str(row["friendly_name"]),
                "target_type": str(row["target_type"]),
            }
            for row in conn.execute(
                """SELECT target_uuid,friendly_name,target_type
                   FROM backup_targets
                   WHERE host_node_id=? AND enabled=1
                   ORDER BY id""",
                (node_id,),
            ).fetchall()
        }
        for item in hosted_targets:
            item.update(target_meta.get(str(item.get("target_uuid")), {}))

        try:
            events = _dashboard_event_history(conn.cursor())
            problems = _dashboard_event_history(conn.cursor(), problems_only=True)
        except Exception:
            events, problems = [], []
    finally:
        conn.close()

    service_map = {
        str(item.get("name")): str(item.get("status") or "unknown")
        for item in snapshot.get("services", [])
    }
    fleet_generation = int(snapshot.get("fleet_generation") or 0)
    file_generation = int(snapshot.get("file_transport_generation") or 0)
    shell_generation = int(snapshot.get("shell_transport_generation") or 0)
    in_sync = (
        fleet_generation > 0
        and file_generation == fleet_generation
        and shell_generation == fleet_generation
    )

    alerts = []
    try:
        alerts = [
            {
                "title": row["title"],
                "worker": row.get("worker", hostname),
                "severity": row["severity"],
            }
            for row in get_active_alerts()
        ]
    except Exception:
        alerts = []

    try:
        seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
        uptime = f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    except (OSError, ValueError, IndexError):
        uptime = "unknown"

    worker_health = {
        "hostname": hostname,
        "node_id": node_id,
        "master_hostname": endpoint.get("hostname") or "unknown",
        "master_ip": endpoint.get("ip") or "unknown",
        "master_port": endpoint.get("port"),
        "overall": snapshot.get("status") or "unknown",
        "services": service_map,
        "fleet_generation": fleet_generation,
        "file_generation": file_generation,
        "shell_generation": shell_generation,
        "in_sync": in_sync,
        "mounts": mounts,
        "shell_connections": shell_connections,
        "backup_jobs": backup_jobs,
        "hosted_targets": hosted_targets,
        "care": local_care_observation(node_id=node_id),
    }

    return LatticeStatus(
        role="worker",
        master_hostname=str(endpoint.get("hostname") or "unknown"),
        master_ip=str(endpoint.get("ip") or "unknown"),
        daemon_status=_service_active("lattice-worker.service"),
        uptime=uptime,
        version="0.1.0",
        workers=[],
        alerts=alerts,
        health={"worker": worker_health},
        events=events,
        problems=problems,
    )

def get_status() -> LatticeStatus:
    """Build one live dashboard snapshot from Lattice's persisted/runtime state."""
    try:
        from lattice.wizard.lifecycle import current_role
        role = current_role()
    except Exception:
        role = None
    if role == "worker":
        return _worker_status()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT w.id, w.hostname, w.status, w.last_heartbeat_at, w.failure_count,
                   SUM(CASE WHEN s.status IN ({HEALTHY_SERVICE_STATUS_SQL}) THEN 1 ELSE 0 END),
                   SUM(CASE WHEN s.status IN ({FAILED_SERVICE_STATUS_SQL}) THEN 1 ELSE 0 END),
                   w.ip
            FROM workers w LEFT JOIN services s ON s.worker_id = w.id
            WHERE w.removed_at IS NULL GROUP BY w.id
            ORDER BY w.hostname COLLATE NOCASE
        """)
        workers = []
        for row in cursor.fetchall():
            workers.append({
                "id": row[0],
                "hostname": row[1],
                "status": row[2] or "unknown",
                "last_seen": row[3] or "—",
                "services_ok": row[5] or 0,
                "services_fail": row[6] or 0,
                "ip": row[7],
                "is_self": row[1] == socket.gethostname(),
            })

        recent_events = _dashboard_event_history(cursor)

        # Keep a separate persisted problem history so routine healthy events
        # cannot wash recent warnings/errors out of the dashboard.  These are
        # historical events only; they do not count as active alerts or health.
        recent_problems = _dashboard_event_history(cursor, problems_only=True)

        alerts = get_active_alerts()
        alert_list = [
            {
                "title": alert["title"],
                "worker": alert.get("worker", alert.get("worker_hostname", "Master")),
                "severity": alert["severity"],
            }
            for alert in alerts
        ]

        config = load_config()
        master_hostname = socket.gethostname()
        master_ip = config.master.ip if hasattr(config.master, "ip") else "127.0.0.1"
        try:
            from lattice.wizard.lifecycle import current_role
            role = current_role() or "unconfigured"
        except Exception:
            role = "unknown"
        service = "lattice-master.service" if role == "master" else "lattice-worker.service"
        daemon_status = _service_active(service)

        try:
            seconds = int(float(Path("/proc/uptime").read_text().split()[0]))
            uptime = f"{seconds // 3600}h {(seconds % 3600) // 60}m"
        except (OSError, ValueError, IndexError):
            uptime = "unknown"

        network = _network_health()
        file_health, shell_health = _transport_health(conn, len(workers))
        fleet = _fleet_health(
            daemon_status, workers, alert_list, network, file_health, shell_health
        )
        node_access = _node_access_status(
            conn, master_hostname, daemon_status, workers
        )
        backup_nodes = _backup_node_statuses(
            conn, master_hostname, workers
        )
        care_nodes = _care_node_statuses(
            conn, master_hostname, workers
        )
        try:
            discovery_network = str(config.wire_format.ufw_subnet)
        except AttributeError:
            discovery_network = "unknown"
        automation = _automation_summary(conn, config)
        health = {
            "fleet": fleet,
            "network": network,
            "file": file_health,
            "shell": shell_health,
            "node_access": node_access,
            "backup_nodes": backup_nodes,
            "care_nodes": care_nodes,
            "discovery_network": discovery_network,
            "automation": automation,
        }
        return LatticeStatus(
            role=role,
            master_hostname=master_hostname,
            master_ip=master_ip,
            daemon_status=daemon_status,
            uptime=uptime,
            version="0.1.0",
            workers=workers,
            alerts=alert_list,
            health=health,
            events=recent_events,
            problems=recent_problems,
        )
    finally:
        conn.close()

# ---- Config change helper ----
def change_setting(stdscr):
    """Interactive config change: show list, pick, enter new value."""
    # Load current config
    config = load_config()
    # Flatten config to a list of (key_path, current_value, description)
    items = []
    for section_name, section in config.model_dump().items():
        if isinstance(section, dict):
            for key, value in section.items():
                if not isinstance(value, (dict, list)):
                    path = f"{section_name}.{key}"
                    if not any(word in key.lower() for word in ("token", "secret", "password", "key")):
                        items.append((path, value))
        else:
            items.append((section_name, section))

    # Build a list of display strings
    display = []
    for idx, (key, val) in enumerate(items):
        display.append(f"{idx+1}) {key}  (current: {val})")

    # Show the list with scroll
    curses.curs_set(0)
    height, width = stdscr.getmaxyx()
    list_height = min(len(display), height - 8)
    list_win = curses.newwin(list_height + 2, width - 4, 2, 2)
    list_win.box()
    list_win.refresh()

    selected = 0
    while True:
        list_win.clear()
        list_win.box()
        for i in range(list_height):
            if i < len(display):
                line = display[i]
                if i == selected:
                    list_win.addstr(i+1, 2, line, curses.A_REVERSE)
                else:
                    list_win.addstr(i+1, 2, line)
        list_win.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(display)
        elif key == curses.KEY_DOWN:
            selected = (selected + 1) % len(display)
        elif key == ord('\n') or key == ord('\r'):
            selected_key, selected_val = items[selected]
            # Ask for new value using custom input handler
            stdscr.clear()
            new_val = _get_input(stdscr, f"Current: '{selected_key}' = {selected_val}\nNew value (empty to cancel): ", 0, 0)
            if new_val:
                try:
                    set_nested_config(config, selected_key, new_val)
                    save_config(config)
                    reload_daemon()
                    stdscr.addstr(3, 0, "✅ Setting updated and daemon reloaded. Press any key to continue.")
                except Exception as e:
                    stdscr.addstr(3, 0, f"❌ Error: {e}. Press any key to continue.")
                stdscr.getch()
            return
        elif key == ord('q') or key == ord('Q'):
            return

def set_nested_config(config, key_path, value):
    """Set a nested config value given a dot‑separated path with validation.

    M32 fix: save the old value, set the new one, validate, and
    rollback if validation fails. This prevents the in-memory config
    from being left in an invalid state when the user enters a bad value.
    """
    parts = key_path.split('.')
    obj = config
    for part in parts[:-1]:
        obj = getattr(obj, part)
    old_value = getattr(obj, parts[-1], None)  # save for rollback
    setattr(obj, parts[-1], value)
    from lattice.core.config import LatticeConfig
    import logging
    logger = logging.getLogger(__name__)
    try:
        LatticeConfig.model_validate(config.model_dump())  # raises if invalid
    except Exception as e:
        setattr(obj, parts[-1], old_value)  # M32: rollback
        logger.error(f"Config validation failed for {key_path}={value!r}; rolled back. Error: {e}")
        raise ValueError(f"Invalid config value: {e}")

# ---- TUI renderer ----
FULL_WIDTH = 70
MAX_DASHBOARD_HEIGHT = 54
MIN_DASHBOARD_WIDTH = 60
MIN_DASHBOARD_HEIGHT = 18
STATUS_REFRESH_SECONDS = 5.0
DISCOVERY_INTERVAL_SECONDS = 10.0


class DiscoveryMonitor:
    """Run bounded mDNS discovery away from the curses/UI thread."""
    def __init__(self, discover_fn=None, interval: float = DISCOVERY_INTERVAL_SECONDS):
        if discover_fn is None:
            from lattice.core.mdns import discover_waiting_workers
            discover_fn = discover_waiting_workers
        self.discover_fn = discover_fn
        self.interval = max(1.0, float(interval))
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._scanning = False
        self._last_scan = None
        self._waiting = []
        self._error = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._run, name="lattice-tui-discovery", daemon=True
        )
        self._thread.start()

    def scan_once(self) -> None:
        with self._lock:
            self._scanning = True
            self._error = None
        try:
            waiting = list(self.discover_fn(timeout=3))
            error = None
        except Exception as exc:
            waiting = []
            error = str(exc)
        finished = time.monotonic()
        with self._lock:
            self._waiting = waiting
            self._error = error
            self._last_scan = finished
            self._scanning = False

    def _run(self) -> None:
        while not self._stop.is_set():
            self.scan_once()
            if self._stop.wait(self.interval):
                break

    def snapshot(self, now: Optional[float] = None) -> Dict[str, Any]:
        now = time.monotonic() if now is None else now
        with self._lock:
            age = None if self._last_scan is None else max(0, int(now - self._last_scan))
            return {
                "scanning": self._scanning,
                "last_scan_age": age,
                "waiting": list(self._waiting),
                "error": self._error,
            }

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=0.2)


def _dashboard_mode(height: int, width: int) -> str:
    if height < MIN_DASHBOARD_HEIGHT or width < MIN_DASHBOARD_WIDTH:
        return "tiny"
    # Keep the compact dashboard through 67x43.  As soon as the terminal is
    # larger in both dimensions (68x44 or greater), use the full mesh view.
    if height <= 43 or width <= 67:
        return "compact"
    return "full"


def _safe_addstr(stdscr, y: int, x: int, text: str, attr: int = 0) -> None:
    max_y, max_x = stdscr.getmaxyx()
    if y < 0 or y >= max_y or x < 0 or x >= max_x:
        return
    room = max(0, max_x - x - 1)
    if room <= 0:
        return
    try:
        stdscr.addstr(y, x, text[:room], attr)
    except curses.error:
        return


def _relative_seconds(seconds: Optional[int]) -> str:
    if seconds is None:
        return "never"
    if seconds <= 1:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m {seconds % 60}s ago"
    return f"{minutes // 60}h {minutes % 60}m ago"


def _relative_timestamp(value: object) -> str:
    if not value:
        return "unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age = max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))
        return _relative_seconds(age)
    except (TypeError, ValueError):
        return "unknown"


def _heartbeat_display(value: object, now: Optional[datetime] = None) -> tuple[str, str]:
    """Return a compact mesh heartbeat label plus freshness state.

    Workers normally report every 10 seconds.  Existing recovery logic treats
    a 30-second gap as stale outage evidence, so the dashboard warns before
    that boundary rather than inventing a separate liveness rule.
    """
    if not value or str(value).strip() in {"", "—", "never", "unknown", "now"}:
        if str(value).strip() == "now":
            return "HB just now", "fresh"
        return "HB UNKNOWN", "unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        current = now or datetime.now(timezone.utc)
        age = max(0, int((current - parsed).total_seconds()))
    except (TypeError, ValueError):
        return "HB UNKNOWN", "unknown"

    if age <= 20:
        state = "fresh"
    elif age < 30:
        state = "warning"
    else:
        state = "stale"
    return f"HB {_relative_seconds(age)}", state


def _mesh_worker_status(
    worker: Dict[str, Any],
    access: Optional[Dict[str, Any]],
    *,
    has_active_alert: bool = False,
    now: Optional[datetime] = None,
) -> str:
    """Summarize whether Lattice can fully use one Worker right now.

    This is a dashboard view only.  It does not replace the persisted Worker
    state machine, heartbeat/service checks, transport monitors, or alerts.
    """
    base = str(worker.get("status") or "unknown").lower()
    if base == "down":
        return "DOWN"
    if base == "disabled":
        return "DISABLED"
    if base == "configuring":
        return "CONFIGURING"
    if base == "needs_attention":
        return "DEGRADED"
    if base not in {"healthy", "degraded"}:
        return "UNKNOWN"
    if base == "degraded" or int(worker.get("services_fail") or 0) > 0:
        return "DEGRADED"

    _hb_label, heartbeat_state = _heartbeat_display(worker.get("last_seen"), now=now)
    if heartbeat_state != "fresh":
        return "DEGRADED"
    if has_active_alert:
        return "DEGRADED"
    if not access:
        return "DEGRADED"
    if not all(bool(access.get(key)) for key in ("file_ok", "shell_ok", "admin_ok")):
        return "DEGRADED"
    return "HEALTHY"


def _mesh_master_status(
    daemon_status: str,
    network_state: str,
    access: Optional[Dict[str, Any]],
    *,
    has_active_alert: bool = False,
) -> str:
    """Summarize whether the local Master is fully operational for Lattice."""
    if daemon_status != "running":
        return "DEGRADED"
    if network_state != "healthy" or has_active_alert or not access:
        return "DEGRADED"
    if not all(bool(access.get(key)) for key in ("file_ok", "shell_ok", "admin_ok")):
        return "DEGRADED"
    return "HEALTHY"


def _mesh_status_color(status: str) -> int:
    if status == "HEALTHY":
        return 4
    if status == "DOWN":
        return 6
    if status == "DEGRADED":
        return 5
    return 3


def _mesh_node_symbol(status: str, pulse_on: bool) -> str:
    if status == "HEALTHY":
        return "●" if pulse_on else "○"
    if status in {"DOWN", "DEGRADED"}:
        return "●"
    return "○"


def _state_icon(state: str) -> str:
    if state in {"healthy", "running"}:
        return "●"
    if state in {"degraded", "stopped", "error"}:
        return "⚠"
    if state in {"idle", "unknown"}:
        return "○"
    return "○"


def _fleet_label(status: LatticeStatus) -> str:
    fleet = status.health.get("fleet", {})
    state = fleet.get("state")
    if state == "healthy":
        return "● HEALTHY"
    if state == "degraded":
        return "⚠ DEGRADED"
    return "○ UNKNOWN"


def _discovery_label(snapshot: Dict[str, Any]) -> str:
    if snapshot.get("scanning"):
        return "◌ SCANNING..."
    if snapshot.get("error"):
        return "⚠ ERROR"
    waiting = len(snapshot.get("waiting", []))
    if waiting:
        return f"○ {waiting} WAITING"
    if snapshot.get("last_scan_age") is not None:
        return "✓ READY"
    return "○ STARTING"


def _worker_color(worker: Dict[str, Any]) -> int:
    state = str(worker.get("status") or "unknown")
    if state == "healthy":
        return curses.color_pair(4)
    if state in {"degraded", "configuring", "needs_attention"}:
        return curses.color_pair(5)
    if state == "down":
        return curses.color_pair(6)
    return curses.color_pair(3)


def _worker_display(worker: Dict[str, Any], pulse_on: bool = True) -> str:
    state = str(worker.get("mesh_status") or worker.get("status") or "unknown").upper()
    icon = _mesh_node_symbol(state, pulse_on)
    host = str(worker.get("hostname") or "unknown")[:18]
    ip = str(worker.get("ip") or "no address")
    return f"{icon} {host:<18} {state:<12} {ip}"


def _waiting_display(worker: Dict[str, Any]) -> str:
    txt = worker.get("txt", {}) if isinstance(worker, dict) else {}
    host = str(txt.get("hostname") or worker.get("host") or "unknown")[:18]
    ip = str(worker.get("addr") or "no address")
    return f"○ {host:<18} WAITING TO PAIR  {ip}"


def _health_lines(status: LatticeStatus) -> List[str]:
    network = status.health.get("network", {"state": "unknown", "label": "Unknown"})
    file_health = status.health.get("file", {"state": "unknown", "label": "Unknown"})
    shell_health = status.health.get("shell", {"state": "unknown", "label": "Unknown"})
    daemon_state = "healthy" if status.daemon_status == "running" else "degraded"
    alert_text = "None" if not status.alerts else f"{len(status.alerts)} active"
    return [
        f"  {_state_icon(daemon_state)} Master daemon   {status.daemon_status.title():<10}  "
        f"{_state_icon(str(network.get('state')))} Network   {network.get('label', 'Unknown')}",
        f"  {_state_icon(str(file_health.get('state')))} File access     {file_health.get('label', 'Unknown'):<20}  "
        f"{_state_icon(str(shell_health.get('state')))} Shell   {shell_health.get('label', 'Unknown')}",
        f"  {'✓' if not status.alerts else '⚠'} Alerts          {alert_text}",
    ]


def _activity_lines(status: LatticeStatus, limit: int) -> List[str]:
    if not status.events:
        return ["  No recent activity yet."]
    lines = []
    for event in status.events[:limit]:
        message = str(event.get("message") or "Event").replace("\n", " ")
        worker = str(event.get("worker") or "Master")
        age = _relative_timestamp(event.get("timestamp"))
        lines.append(f"  {worker}: {message}  [{age}]")
    return lines


def _recent_log_row(event: Dict[str, Any], width: int) -> tuple[str, int]:
    """Format one recent persisted Lattice event for the dashboard log strip."""
    severity = str(event.get("severity") or "info").lower()
    if severity in {"error", "critical"}:
        marker, color = "✗", 6
    elif severity in {"warn", "warning"}:
        marker, color = "⚠", 5
    elif severity in {"ok", "info", "success"}:
        marker, color = "●", 4
    else:
        marker, color = "○", 3

    age = _relative_timestamp(event.get("timestamp"))
    worker = str(event.get("worker") or "Master")[:18]
    message = str(event.get("message") or "Event").replace("\n", " ").strip()
    prefix = f"{marker} {age:<12} {worker:<18} "
    room = max(0, width - len(prefix))
    return prefix + message[:room], color


def _recent_problem_row(event: Dict[str, Any], width: int) -> tuple[str, int, Optional[tuple[int, str, int]]]:
    """Format a problem plus its proven outcome in one fixed-height row."""
    base_row, color = _recent_log_row(event, width)
    outcome = str(event.get("outcome") or "").strip().upper()
    if not outcome:
        return base_row, color, None

    suffix = f"→ {outcome}"
    severity = str(event.get("severity") or "info").lower()
    marker = "✗" if severity in {"error", "critical"} else "⚠"
    age = _relative_timestamp(event.get("timestamp"))
    worker = str(event.get("worker") or "Master")[:14]
    message = str(event.get("message") or "Event").replace("\n", " ").strip()
    prefix = f"{marker} {age:<12} {worker:<14} "
    room = max(0, width - len(prefix) - len(suffix) - 1)
    row = prefix + message[:room].ljust(room) + " " + suffix
    row = row[:width]
    outcome_pos = row.rfind(suffix)

    if outcome in {"RECOVERED", "REPAIRED", "RESTARTED", "RESOLVED"}:
        outcome_color = 4
    elif outcome in {"FAILED", "STOPPED"}:
        outcome_color = 6
    else:
        outcome_color = 5
    overlay = (outcome_pos, suffix, outcome_color) if outcome_pos >= 0 else None
    return row, color, overlay


def _passive_discovery_snapshot() -> Dict[str, Any]:
    return {"scanning": False, "last_scan_age": None, "waiting": [], "error": None}


def _modal_getch(stdscr) -> int:
    """Wait for a real key on modal workflow pages, then restore live refresh."""
    if hasattr(stdscr, "timeout"):
        stdscr.timeout(-1)
    try:
        return stdscr.getch()
    finally:
        if hasattr(stdscr, "timeout"):
            stdscr.timeout(1000)


def _flow_message(stdscr, title: str, lines: List[str], footer: str = "") -> None:
    """Draw a simple full-screen workflow page inside the existing curses UI."""
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()
    width = min(FULL_WIDTH, max(20, max_x - 2))
    x = max(0, (max_x - width) // 2)
    _safe_addstr(stdscr, 1, x, f"  {title}", curses.color_pair(2) | curses.A_BOLD)
    _safe_addstr(stdscr, 2, x, "─" * width, curses.color_pair(1))
    y = 4
    for line in lines:
        wrapped = textwrap.wrap(str(line), max(10, width - 4)) or [""]
        for part in wrapped:
            if y >= max_y - 2:
                break
            _safe_addstr(stdscr, y, x + 2, part, curses.color_pair(3))
            y += 1
    if footer and max_y >= 2:
        _safe_addstr(stdscr, max_y - 2, x + 2, footer, curses.color_pair(3))
    stdscr.refresh()


def _add_worker_flow(stdscr, discovery_monitor: Optional[DiscoveryMonitor]) -> None:
    """Pair one discovered Worker without ever leaving the curses dashboard."""
    selected = 0
    while True:
        discovery = (
            discovery_monitor.snapshot()
            if discovery_monitor is not None
            else _passive_discovery_snapshot()
        )
        workers = list(discovery.get("waiting", []))
        if not workers:
            detail = "No reachable computers are currently waiting to pair."
            if discovery.get("error"):
                detail = f"Discovery error: {discovery['error']}"
            _flow_message(
                stdscr, "ADD COMPUTER",
                [detail, "Start Lattice Worker setup on the other computer and leave its pairing screen open."],
                "Press any key to return to the Fleet Dashboard.",
            )
            _modal_getch(stdscr)
            return

        selected = min(selected, len(workers) - 1)
        lines = ["Choose a computer to securely add to this fleet:", ""]
        for index, worker in enumerate(workers):
            txt = worker.get("txt", {}) if isinstance(worker, dict) else {}
            host = str(txt.get("hostname") or worker.get("host") or "unknown")
            addr = str(worker.get("addr") or "no address")
            marker = "▶" if index == selected else " "
            lines.append(f"{marker} {host:<22} {addr:<15} WAITING TO PAIR")
        _flow_message(stdscr, "ADD COMPUTER", lines, "↑/↓ choose   Enter select   Q cancel")
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(workers)
            continue
        if key == curses.KEY_DOWN:
            selected = (selected + 1) % len(workers)
            continue
        if key in (ord('q'), ord('Q')):
            return
        if key not in (ord('\n'), ord('\r'), curses.KEY_ENTER):
            continue

        worker = workers[selected]
        txt = worker.get("txt", {}) if isinstance(worker, dict) else {}
        hostname = str(txt.get("hostname") or worker.get("host") or "unknown")
        worker_ip = str(worker.get("addr") or "")
        pairing_id = str(txt.get("pairing_id") or "")
        if not worker_ip or not pairing_id:
            _flow_message(
                stdscr, "ADD COMPUTER",
                [f"{hostname} did not publish a complete pairing offer."],
                "Press any key to return to the Fleet Dashboard.",
            )
            _modal_getch(stdscr)
            return

        _flow_message(
            stdscr, "ADD COMPUTER",
            [f"Computer: {hostname}", f"Temporary address: {worker_ip}",
             "Enter the pairing code currently shown on that Worker's screen."],
        )
        code = _get_input(stdscr, "Pairing code: ", 8, 2).strip()
        if not code:
            return

        _flow_message(
            stdscr, "PAIRING COMPUTER",
            [f"Computer: {hostname}",
             "Pairing request sent.",
             "On the Worker, press A when it asks for local approval.",
             "Lattice is securely verifying credentials, SSH access, and network assignment..."],
            "Keep both computers on and connected while pairing completes.",
        )
        try:
            from lattice.pairing import pair_worker
            result = pair_worker(
                hostname=hostname,
                worker_ip=worker_ip,
                pairing_id=pairing_id,
                code=code,
            )
        except Exception as exc:
            _flow_message(
                stdscr, "PAIRING FAILED",
                [f"Could not pair {hostname}.", str(exc)],
                "Press any key to return to the Fleet Dashboard.",
            )
            _modal_getch(stdscr)
            return

        _flow_message(
            stdscr, "COMPUTER ADDED",
            [f"✓ {result.get('hostname', hostname)} paired securely.",
             f"Permanent Lattice address: {result.get('ip', 'assigned')}",
             "The Fleet Dashboard will refresh with the new node."],
            "Press any key to return to the Fleet Dashboard.",
        )
        _modal_getch(stdscr)
        return


# ---- Finished dashboard control workflows ----
def _control_menu(
    stdscr,
    title: str,
    options: List[str],
    *,
    intro: Optional[List[str]] = None,
    help_texts: Optional[List[List[str]]] = None,
) -> Optional[int]:
    """Simple curses menu used by footer workflows; returns an index or None."""
    if not options:
        return None
    selected = 0
    page_start = 0
    while True:
        max_y, _max_x = stdscr.getmaxyx()
        intro_lines = list(intro or [])
        # Leave room for title/rule/footer, intro, optional scroll hints, and
        # help text. Long menus must render a moving window rather than being
        # silently clipped by _flow_message().
        page_size = max(3, max_y - 10 - len(intro_lines))
        page_size = min(page_size, len(options))

        if selected < page_start:
            page_start = selected
        elif selected >= page_start + page_size:
            page_start = selected - page_size + 1
        page_start = max(0, min(page_start, max(0, len(options) - page_size)))
        page_end = min(len(options), page_start + page_size)

        lines = intro_lines
        if lines:
            lines.append("")
        if page_start > 0:
            lines.append("↑ more above")
        for index in range(page_start, page_end):
            option = options[index]
            marker = "▶" if index == selected else " "
            lines.append(f"{marker} [{index + 1}] {option}")
        if page_end < len(options):
            lines.append("↓ more below")
        if help_texts and selected < len(help_texts):
            details = help_texts[selected]
            if details:
                lines.extend(["", "ABOUT THIS SETTING"])
                lines.extend(details)
        _flow_message(
            stdscr,
            title,
            lines,
            "↑/↓ Select   PgUp/PgDn Page   Enter Open   Number Select   Q Back",
        )
        key = _modal_getch(stdscr)
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(options)
            continue
        if key == curses.KEY_DOWN:
            selected = (selected + 1) % len(options)
            continue
        if key == curses.KEY_PPAGE:
            selected = max(0, selected - page_size)
            continue
        if key == curses.KEY_NPAGE:
            selected = min(len(options) - 1, selected + page_size)
            continue
        if ord('1') <= key <= ord('9'):
            direct = key - ord('1')
            if direct < len(options):
                return direct
        if key in (ord('q'), ord('Q'), 27):
            return None
        if key in (ord('\n'), ord('\r'), curses.KEY_ENTER):
            return selected


def _control_text_input(stdscr, title: str, prompt: str, *, secret: bool = False, initial: str = "") -> Optional[str]:
    """Read one value entirely inside curses. Escape cancels; secrets are masked."""
    value = initial
    try:
        curses.curs_set(1)
    except curses.error:
        pass
    if hasattr(stdscr, "timeout"):
        stdscr.timeout(-1)
    try:
        while True:
            shown = "•" * len(value) if secret else value
            _flow_message(
                stdscr,
                title,
                [*str(prompt).splitlines(), "", f"> {shown}"],
                "Enter Save   Backspace Delete   Esc Cancel",
            )
            key = stdscr.getch()
            if key in (ord('\n'), ord('\r'), curses.KEY_ENTER):
                return value
            if key == 27:
                return None
            if key in (curses.KEY_BACKSPACE, 127, 8):
                value = value[:-1]
                continue
            if key == curses.KEY_RESIZE:
                continue
            if 32 <= key <= 126:
                value += chr(key)
    finally:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if hasattr(stdscr, "timeout"):
            stdscr.timeout(1000)


def _control_result(stdscr, title: str, lines: List[str]) -> None:
    _flow_message(stdscr, title, lines, "Press any key to return.")
    _modal_getch(stdscr)


def _human_size(value: object) -> str:
    try:
        size = max(0, int(value or 0))
    except (TypeError, ValueError):
        return "Unknown size"
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    number = float(size)
    for unit in units:
        if number < 1000.0 or unit == units[-1]:
            return f"{number:.1f} {unit}" if unit != "B" else f"{int(number)} B"
        number /= 1000.0
    return f"{size} B"


def _backup_overview_flow(stdscr) -> None:
    from lattice.operator_interface import execute_operator_request
    try:
        payload = execute_operator_request({"command": "backups.jobs", "params": {}})
        jobs = payload["data"]
    except Exception as exc:
        _control_result(stdscr, "BACKUPS", ["Could not load backup status.", str(exc)])
        return
    if not jobs:
        _control_result(
            stdscr, "BACKUPS",
            ["No backups are configured yet.", "Choose Set Up Backup to protect a computer's Home folder."],
        )
        return
    lines = []
    labels = {
        "healthy": "Healthy", "running": "Running", "pending": "Waiting to retry",
        "paused": "Paused", "never_backed_up": "No successful backup yet", "unknown": "Waiting for status",
    }
    for job in jobs:
        state = labels.get(str(job.get("state") or "unknown"), str(job.get("state") or "Unknown"))
        last = str(job.get("last_success_at") or "Never")
        lines.extend([
            f"{job['source_hostname']} → {job['target_name']}",
            f"  Status: {state}",
            f"  Last successful backup: {last}",
        ])
        if job.get("pause_reason"):
            lines.append(f"  Reason: {job['pause_reason']}")
        lines.append("")
    _control_result(stdscr, "BACKUP OVERVIEW", lines[:-1])


def _backup_control(*args: str) -> dict:
    command = [
        "/usr/bin/sudo", "-n", "/opt/lattice/bin/lattice-backup-control",
        *[str(value) for value in args],
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not start the restricted backup helper: {exc}") from exc
    payload = None
    for line in reversed((result.stdout or "").splitlines()):
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict):
            payload = candidate
            break
    if result.returncode != 0:
        message = (payload or {}).get("message") if payload else None
        detail = message or (result.stderr or result.stdout or "Backup action failed").strip()
        raise RuntimeError(str(detail)[:1000])
    if not isinstance(payload, dict):
        raise RuntimeError("Backup helper returned an invalid response")
    return payload


def _setup_backup_flow(stdscr) -> None:
    from lattice.backup.catalog import (
        backup_source_computers, registered_backup_targets, fleet_storage_candidates,
    )
    sources = backup_source_computers()
    if not sources:
        _control_result(stdscr, "SET UP BACKUP", ["No active Lattice computers are available."])
        return
    source_choice = _control_menu(
        stdscr, "SET UP BACKUP — 1 OF 3",
        [str(item["hostname"]) for item in sources],
        intro=["Which computer do you want to protect?", "Lattice Backup protects that computer's Home folder."],
    )
    if source_choice is None:
        return
    source = sources[source_choice]
    targets = registered_backup_targets()
    candidates = [item for item in fleet_storage_candidates() if not item["registered"]]
    options = []
    choices = []
    for target in targets:
        options.append(f"{target['friendly_name']} — on {target['host_hostname']}")
        choices.append(("target", target))
    for item in candidates:
        kind = "External drive" if item["removable"] else "Internal storage"
        options.append(
            f"{item['host_hostname']} — {kind} — {_human_size(item['size_bytes'])} — {item['filesystem_type']}"
        )
        choices.append(("candidate", item))
    if not options:
        _control_result(
            stdscr, "SET UP BACKUP",
            ["No backup destinations are currently available.",
             "Plug in and mount a drive on a Lattice computer, then try again."],
        )
        return
    target_choice = _control_menu(
        stdscr, "SET UP BACKUP — 2 OF 3", options,
        intro=["Where should this computer's encrypted backup be stored?",
               "Detected drives are read-only discoveries; Lattice will not format or erase them."],
    )
    if target_choice is None:
        return
    choice_kind, choice = choices[target_choice]
    if choice_kind == "target":
        target_name = str(choice["friendly_name"])
        host_name = str(choice["host_hostname"])
    else:
        host_name = str(choice["host_hostname"])
        suggested = f"{host_name} Backup Drive"
        entered = _control_text_input(
            stdscr, "NAME BACKUP DRIVE",
            "Give this backup destination a friendly name.", initial=suggested,
        )
        if entered is None:
            return
        target_name = entered.strip()
        if not target_name:
            _control_result(stdscr, "SET UP BACKUP", ["A backup destination name is required."])
            return
    confirmation = _control_menu(
        stdscr, "SET UP BACKUP — 3 OF 3", ["Create Backup", "Cancel"],
        intro=[
            f"Protect: {source['hostname']}'s Home folder",
            f"Store on: {target_name} ({host_name})",
            "Schedule: Nightly, with automatic catch-up if a backup is missed",
            "Storage: Encrypted, versioned, deduplicated snapshots",
        ],
    )
    if confirmation != 0:
        return
    try:
        target_ref = (
            str(choice["candidate_id"])
            if choice_kind == "candidate"
            else str(choice["id"])
        )
        _backup_control(
            "setup", str(source["node_id"]), choice_kind, target_ref, target_name
        )
    except RuntimeError as exc:
        _control_result(stdscr, "BACKUP NOT CREATED", [str(exc)])
        return
    _control_result(
        stdscr, "BACKUP CREATED",
        [f"✓ {source['hostname']} → {target_name}",
         "The backup will run nightly and catch up automatically when needed."],
    )


def _manage_backup_targets_flow(stdscr) -> None:
    from lattice.operator_interface import execute_operator_request
    try:
        targets = execute_operator_request(
            {"command": "backups.targets", "params": {}}
        )["data"]
        candidates = execute_operator_request(
            {"command": "backups.candidates", "params": {}}
        )["data"]
    except Exception as exc:
        _control_result(stdscr, "BACKUP TARGETS", ["Could not load backup storage.", str(exc)])
        return
    lines = ["REGISTERED TARGETS"]
    if targets:
        for item in targets:
            presence = "Connected" if item.get("present") else "Unavailable"
            free = ""
            if item.get("free_bytes") is not None:
                free = f" — {_human_size(item['free_bytes'])} free"
            lines.append(f"• {item['friendly_name']} — {item['host_hostname']} — {presence}{free}")
    else:
        lines.append("• None yet")
    lines.extend(["", "DETECTED STORAGE"])
    available = [item for item in candidates if not item.get("registered")]
    if available:
        for item in available:
            kind = "External" if item.get("removable") else "Internal"
            lines.append(
                f"• {item['host_hostname']} — {kind} — {_human_size(item['size_bytes'])} — {item['filesystem_type']}"
            )
    else:
        lines.append("• No new mounted drives detected")
    lines.extend(["", "Drive UUIDs, device paths, and mountpoints are available only in Advanced diagnostics."])
    _control_result(stdscr, "BACKUP TARGETS", lines)


def _pause_resume_backup_flow(stdscr) -> None:
    from lattice.operator_interface import execute_operator_request
    try:
        jobs = execute_operator_request({"command": "backups.jobs", "params": {}})["data"]
    except Exception as exc:
        _control_result(stdscr, "PAUSE / RESUME", [str(exc)])
        return
    if not jobs:
        _control_result(stdscr, "PAUSE / RESUME", ["No backup jobs are configured."])
        return
    choice = _control_menu(
        stdscr, "PAUSE / RESUME BACKUP",
        [
            f"{item['source_hostname']} → {item['target_name']} — {'Paused' if item['paused'] else 'Active'}"
            for item in jobs
        ],
    )
    if choice is None:
        return
    job = jobs[choice]
    try:
        if job["paused"]:
            _backup_control("resume", str(job["job_id"]))
            message = "Backup resumed. Missed protection will catch up automatically."
        else:
            reason = _control_text_input(
                stdscr, "PAUSE BACKUP", "Why are you pausing this backup?"
            )
            if reason is None:
                return
            _backup_control("pause", str(job["job_id"]), reason)
            message = "Backup paused. Its configuration and existing snapshots were not deleted."
    except RuntimeError as exc:
        _control_result(stdscr, "BACKUP CHANGE FAILED", [str(exc)])
        return
    _control_result(stdscr, "BACKUP UPDATED", [message])


def _backup_now_flow(stdscr) -> None:
    from lattice.operator_interface import execute_operator_request
    try:
        jobs = execute_operator_request(
            {"command": "backups.jobs", "params": {}}
        )["data"]
    except Exception as exc:
        _control_result(stdscr, "BACK UP NOW", [str(exc)])
        return
    active = [item for item in jobs if not item.get("paused")]
    if not active:
        _control_result(stdscr, "BACK UP NOW", ["No active backup jobs are available."])
        return
    choice = _control_menu(
        stdscr, "BACK UP NOW",
        [f"{item['source_hostname']} → {item['target_name']}" for item in active],
        intro=["Choose a backup to run immediately.",
               "This uses the same verified path as the nightly backup."],
    )
    if choice is None:
        return
    job = active[choice]
    remote = str(job.get("target_type") or "") == "remote_storage"
    if remote:
        confirm = _control_menu(
            stdscr,
            "CONFIRM BACKUP",
            [
                "Start Backup — use normal configured network speed",
                "Full Speed — temporarily remove the backup bandwidth cap",
                "Confirm Large First Backup — only after Lattice asks for confirmation",
                "Cancel",
            ],
            intro=[
                f"{job['source_hostname']} → {job['target_name']}",
                "Full Speed applies to this backup only; it does not change your saved setting.",
                "Large confirmation only bypasses the 200 GiB first-backup confirmation threshold.",
            ],
        )
        if confirm is None or confirm == 3:
            return
        full_speed = confirm == 1
        allow_large_first_backup = confirm == 2
    else:
        confirm = _control_menu(
            stdscr,
            "CONFIRM BACKUP",
            [
                "Start Backup",
                "Confirm Large First Backup — only after Lattice asks for confirmation",
                "Cancel",
            ],
            intro=[
                f"{job['source_hostname']} → {job['target_name']}",
                "The source computer will perform this local-storage backup now.",
                "Large confirmation only bypasses the 200 GiB first-backup confirmation threshold.",
            ],
        )
        if confirm is None or confirm == 2:
            return
        full_speed = False
        allow_large_first_backup = confirm == 1
    try:
        args = ["run-now", str(job["job_uuid"])]
        if full_speed:
            args.append("--full-speed")
        if allow_large_first_backup:
            args.append("--confirm-large-backup")
        result = _backup_control(*args)
    except RuntimeError as exc:
        _control_result(stdscr, "BACKUP NOT STARTED", [str(exc)])
        return
    status = str(result.get("status") or "accepted")
    message = (
        "That backup request was already waiting to run."
        if status == "already_pending"
        else "Backup request accepted. Progress will appear in Overview and History."
    )
    _control_result(stdscr, "BACKUP STARTED", [message])


def _restore_backup_selection_flow(
    stdscr,
    *,
    job: dict,
    snapshot_id: str,
    selection: str,
    source_root: str,
) -> None:
    from pathlib import PurePosixPath

    selected = PurePosixPath(selection)
    _flow_message(
        stdscr,
        "PREPARING RESTORE",
        [
            f"Item: {selected.name or selection}",
            f"From: {job['source_hostname']} backup",
            "",
            "Lattice is restoring this selection into protected staging first.",
            "Nothing is being written into your Home folder yet.",
        ],
        "Please wait while the selected backup data is verified and staged.",
    )
    try:
        staged = _backup_control(
            "restore-stage",
            str(job["job_uuid"]),
            snapshot_id,
            selection,
        )
    except RuntimeError as exc:
        _control_result(stdscr, "RESTORE NOT PREPARED", [str(exc)])
        return

    session_uuid = str(staged.get("session_uuid") or "")
    if not session_uuid:
        _control_result(stdscr, "RESTORE NOT PREPARED", ["Lattice did not return a restore session."])
        return
    original = str(staged.get("original_destination") or selection)
    conflict = bool(staged.get("conflict"))
    item_type = str(staged.get("type") or "item").title()
    size = _human_size(staged.get("size"))

    intro = [
        f"{item_type}: {selected.name or selection}",
        f"Size: {size}",
        f"Original location: {original}",
        "",
    ]
    if conflict:
        intro.extend([
            "Something already exists at the original location.",
            "Choose exactly how you want Lattice to handle that conflict.",
        ])
    else:
        intro.extend([
            "The original location is currently free.",
            "Keep Both is still available if you prefer a separate restored copy.",
        ])

    choice = _control_menu(
        stdscr,
        "RESTORE — CHOOSE DESTINATION",
        [
            "Keep Both — safest; restore as a separate copy",
            "Replace — put the backup at the original location",
            "Elsewhere — choose another location inside this Home folder",
            "Cancel — do not restore",
        ],
        intro=intro,
    )
    if choice is None or choice == 3:
        try:
            _backup_control(
                "restore-cancel",
                str(job["job_uuid"]),
                session_uuid,
            )
        except RuntimeError as exc:
            _control_result(
                stdscr,
                "RESTORE CANCEL WARNING",
                ["The restore was not placed, but staging cleanup reported:", str(exc)],
            )
        return

    action = "keep_both" if choice == 0 else "replace" if choice == 1 else "elsewhere"
    args = [
        "restore-place",
        str(job["job_uuid"]),
        session_uuid,
        action,
    ]
    if action == "elsewhere":
        suggested = str(PurePosixPath(source_root) / "Restored" / (selected.name or "restored-item"))
        destination = _control_text_input(
            stdscr,
            "RESTORE ELSEWHERE",
            "Enter a new destination inside this computer's Home folder.",
            initial=suggested,
        )
        if destination is None:
            try:
                _backup_control("restore-cancel", str(job["job_uuid"]), session_uuid)
            except RuntimeError:
                pass
            return
        args.append(destination.strip())

    _flow_message(
        stdscr,
        "RESTORING",
        [
            f"Item: {selected.name or selection}",
            "",
            "The verified staged copy is now being placed at the selected destination.",
        ],
        "Lattice will preserve the existing item until Replace can complete safely.",
    )
    try:
        placed = _backup_control(*args)
    except RuntimeError as exc:
        _control_result(
            stdscr,
            "RESTORE FAILED SAFELY",
            [str(exc), "The staged restore was not reported as successfully placed."],
        )
        return
    _control_result(
        stdscr,
        "RESTORE COMPLETE",
        [
            "✓ Restore completed successfully.",
            f"Restored to: {placed.get('destination') or 'selected destination'}",
        ],
    )


def _full_home_recovery_preflight_flow(
    stdscr,
    *,
    job: dict,
    snapshot_id: str,
    snapshot_time: str,
) -> None:
    _flow_message(
        stdscr,
        "FULL HOME RECOVERY CHECK",
        [
            f"Computer: {job['source_hostname']}",
            f"Snapshot: {snapshot_time}",
            "",
            "Lattice is checking recovery size, free space, and account identity.",
            "This check is read-only and does not restore or replace any files.",
        ],
        "Please wait while the source computer inspects this recovery point.",
    )
    try:
        result = _backup_control(
            "recovery-preflight",
            str(job["job_uuid"]),
            snapshot_id,
        )
    except RuntimeError as exc:
        _control_result(stdscr, "RECOVERY CHECK FAILED", [str(exc)])
        return
    preflight = result.get("preflight")
    if not isinstance(preflight, dict):
        _control_result(
            stdscr,
            "RECOVERY CHECK FAILED",
            ["The source computer returned an invalid recovery preflight result."],
        )
        return
    ready = bool(preflight.get("ready_for_offline_recovery"))
    lines = [
        "✓ READY FOR OFFLINE RECOVERY" if ready else "✗ NOT READY FOR FULL HOME RECOVERY",
        "",
        f"Home: {preflight.get('source_path') or 'Unknown'}",
        f"Snapshot status: {'Backup completed' if preflight.get('snapshot_completed') else 'Completion not recorded'}",
        f"Snapshot restore size: {_human_size(preflight.get('snapshot_restore_bytes'))}",
        f"Files in snapshot: {preflight.get('snapshot_file_count', 0)}",
        f"Expected account: {preflight.get('source_user') or 'Unknown'} "
        f"(UID {preflight.get('expected_uid')}, GID {preflight.get('expected_gid')})",
        f"Account identity: {'Matches' if preflight.get('account_matches_expected') else 'Does not match'}",
        f"Staging free: {_human_size(preflight.get('staging_free_bytes'))}",
        f"Home filesystem free: {_human_size(preflight.get('home_free_bytes'))}",
        f"Space check: {'Pass' if preflight.get('space_ok') else 'Blocked'}",
    ]
    if preflight.get("staging_and_home_same_filesystem"):
        lines.extend([
            "",
            "Staging and Home share one filesystem.",
            "Protected recovery therefore needs temporary room for both the staged and placed copies.",
            f"Required free space: {_human_size(preflight.get('required_staging_free_bytes'))}",
        ])
    else:
        lines.extend([
            "",
            f"Required staging free: {_human_size(preflight.get('required_staging_free_bytes'))}",
            f"Required Home free: {_human_size(preflight.get('required_home_free_bytes'))}",
        ])
    blockers = list(preflight.get("blockers") or [])
    warnings = list(preflight.get("warnings") or [])
    if blockers:
        lines.extend(["", "BLOCKERS"])
        lines.extend(f"• {value}" for value in blockers[:12])
    if warnings:
        lines.extend(["", "WARNINGS"])
        lines.extend(f"• {value}" for value in warnings[:12])
    lines.extend([
        "",
        "Live wholesale Home replacement is intentionally disabled.",
        "Full Home Recovery will require the dedicated offline recovery workflow.",
    ])
    _control_result(stdscr, "FULL HOME RECOVERY CHECK", lines)


def _browse_backup_job_flow(stdscr, job: dict) -> None:
    """Browse/restore one already-authorized Backup job."""
    from pathlib import PurePosixPath
    try:
        snapshot_result = _backup_control("snapshots", str(job["job_uuid"]))
    except RuntimeError as exc:
        _control_result(stdscr, "BROWSE BACKUPS", [str(exc)])
        return
    snapshots = snapshot_result.get("snapshots") or []
    if not snapshots:
        _control_result(
            stdscr,
            "BROWSE BACKUPS",
            ["No snapshots are available for this backup yet."],
        )
        return

    snapshot_choice = _control_menu(
        stdscr,
        "CHOOSE BACKUP DATE",
        [
            f"{item.get('time') or 'Unknown date'} — "
            f"{'Verified' if item.get('health') == 'verified' else 'Health unknown'}"
            for item in snapshots
        ],
        intro=[f"{job['source_hostname']} → {job['target_name']}",
               "Newest backups are shown first."],
    )
    if snapshot_choice is None:
        return
    snapshot = snapshots[snapshot_choice]
    snapshot_id = str(snapshot["snapshot_id"])
    source_root = str(snapshot_result.get("source_root") or "")
    if not source_root.startswith("/home/"):
        _control_result(stdscr, "BROWSE BACKUPS", ["The backup source root is invalid."])
        return
    while True:
        snapshot_action = _control_menu(
            stdscr,
            "BACKUP SNAPSHOT",
            ["Browse Files and Folders", "Full Home Recovery Check", "Back"],
            intro=[
                f"{job['source_hostname']} → {job['target_name']}",
                str(snapshot.get("time") or "Backup snapshot"),
            ],
        )
        if snapshot_action is None or snapshot_action == 2:
            return
        if snapshot_action == 1:
            _full_home_recovery_preflight_flow(
                stdscr,
                job=job,
                snapshot_id=snapshot_id,
                snapshot_time=str(snapshot.get("time") or "Unknown date"),
            )
            continue
        break

    current = PurePosixPath(source_root)
    root = current

    while True:
        try:
            result = _backup_control(
                "browse",
                str(job["job_uuid"]),
                snapshot_id,
                str(current),
            )
        except RuntimeError as exc:
            _control_result(stdscr, "BROWSE BACKUPS", [str(exc)])
            return
        entries = list(result.get("entries") or [])
        entries.sort(
            key=lambda item: (
                str(item.get("type")) != "dir",
                str(item.get("name") or "").casefold(),
            )
        )
        options = []
        actions = []
        if current != root:
            options.append("↑ Up one folder")
            actions.append(("up", None))
        for item in entries:
            name = str(item.get("name") or "")
            entry_type = str(item.get("type") or "unknown")
            if entry_type == "dir":
                options.append(f"📁 {name}")
            else:
                options.append(f"   {name} — {_human_size(item.get('size'))}")
            actions.append((entry_type, item))
        options.append("Back")
        actions.append(("back", None))
        selected = _control_menu(
            stdscr,
            f"BACKUP: {current.name or '/'}",
            options,
            intro=[str(snapshot.get("time") or "Backup snapshot"),
                   "Folders first. Choose a file to view its details."],
        )
        if selected is None:
            return
        action, item = actions[selected]
        if action == "back":
            return
        if action == "up":
            parent = current.parent
            try:
                parent.relative_to(root)
            except ValueError:
                parent = root
            current = parent
            continue
        assert isinstance(item, dict)
        path = PurePosixPath(str(item.get("path") or ""))
        try:
            path.relative_to(root)
        except ValueError:
            _control_result(stdscr, "BROWSE BACKUPS", ["Backup entry escaped the protected Home folder."])
            return
        if action == "dir":
            folder_choice = _control_menu(
                stdscr,
                "BACKUP FOLDER",
                ["Open Folder", "Restore This Folder", "Back"],
                intro=[
                    f"Folder: {item.get('name')}",
                    f"Modified: {item.get('modified_at') or 'Unknown'}",
                ],
            )
            if folder_choice == 0:
                current = path
            elif folder_choice == 1:
                _restore_backup_selection_flow(
                    stdscr,
                    job=job,
                    snapshot_id=snapshot_id,
                    selection=str(path),
                    source_root=source_root,
                )
            continue
        file_choice = _control_menu(
            stdscr,
            "BACKUP FILE",
            ["Restore This File", "Back"],
            intro=[
                f"Name: {item.get('name')}",
                f"Size: {_human_size(item.get('size'))}",
                f"Modified: {item.get('modified_at') or 'Unknown'}",
            ],
        )
        if file_choice == 0:
            _restore_backup_selection_flow(
                stdscr,
                job=job,
                snapshot_id=snapshot_id,
                selection=str(path),
                source_root=source_root,
            )



def _browse_backups_flow(stdscr) -> None:
    from lattice.operator_interface import execute_operator_request

    try:
        jobs = execute_operator_request(
            {"command": "backups.jobs", "params": {}}
        )["data"]
    except Exception as exc:
        _control_result(stdscr, "BROWSE BACKUPS", [str(exc)])
        return
    if not jobs:
        _control_result(stdscr, "BROWSE BACKUPS", ["No backup jobs are configured."])
        return

    choice = _control_menu(
        stdscr,
        "BROWSE BACKUPS",
        [f"{item['source_hostname']} → {item['target_name']}" for item in jobs],
        intro=["Choose the backup you want to browse."],
    )
    if choice is None:
        return
    _browse_backup_job_flow(stdscr, jobs[choice])


def _backup_settings_flow(stdscr) -> None:
    """Open only the user-facing Backup policy settings."""
    category = next(
        (items for name, items in _SETTINGS_CATEGORIES if name == "Backup"),
        None,
    )
    if category is None:
        _control_result(stdscr, "BACKUP SETTINGS", ["Backup settings are unavailable."])
        return
    items = category
    while True:
        try:
            config = load_config()
        except Exception as exc:
            _control_result(stdscr, "BACKUP SETTINGS", [f"Could not load Backup settings: {exc}"])
            return
        labels = []
        help_texts = []
        for path, label, _description, unit in items:
            value = _nested_value(config, path)
            labels.append(f"{label:<30} {_format_setting_value(value, unit)}")
            help_texts.append(_setting_help(path, config))
        item_index = _control_menu(
            stdscr,
            "BACKUP SETTINGS",
            labels,
            help_texts=help_texts,
            intro=[
                "Simple defaults are already configured; change only what you need.",
                "Backup credentials, repository IDs, and transport details stay protected.",
            ],
        )
        if item_index is None:
            return
        path, label, description, unit = items[item_index]
        current = _nested_value(config, path)
        raw_input = _control_text_input(
            stdscr,
            label.upper(),
            f"{description}\nCurrent: {_format_setting_value(current, unit)}\nEnter the new numeric value:",
        )
        if raw_input is None or not raw_input.strip():
            continue
        try:
            updated = _validated_config_update(config, path, raw_input.strip())
            save_config(updated)
            reloaded = reload_daemon()
        except Exception as exc:
            _control_result(
                stdscr, "SETTING NOT CHANGED",
                [f"✗ {label} was not changed.", str(exc)],
            )
            continue
        new_value = _nested_value(updated, path)
        _control_result(
            stdscr,
            "SETTING SAVED",
            [
                f"✓ {label} saved as {_format_setting_value(new_value, unit)}.",
                (
                    "✓ Running Master acknowledged the configuration reload."
                    if reloaded
                    else "⚠ Setting saved, but the running Master did not confirm the configuration reload."
                ),
                _setting_apply_note(path),
            ],
        )


def _backup_history_flow(stdscr) -> None:
    from lattice.operator_interface import execute_operator_request
    try:
        rows = execute_operator_request(
            {"command": "backups.runs", "params": {"limit": 50}}
        )["data"]
    except Exception as exc:
        _control_result(stdscr, "BACKUP HISTORY", [str(exc)])
        return
    if not rows:
        _control_result(stdscr, "BACKUP HISTORY", ["No backup attempts have been recorded yet."])
        return
    lines = []
    for row in rows:
        when = str(row.get("started_at") or "Unknown time")
        result = str(row.get("result") or "unknown").replace("_", " ").title()
        lines.append(
            f"{when} — {row['source_hostname']} → {row['target_name']} — {result}"
        )
    _control_result(stdscr, "BACKUP HISTORY", lines)


def _backups_flow(stdscr) -> None:
    while True:
        choice = _control_menu(
            stdscr, "BACKUPS",
            ["Overview", "Set Up Backup", "Back Up Now", "Browse Backups", "Manage Targets", "Pause / Resume", "Backup Settings", "History", "Back"],
            intro=["Encrypted, versioned Home backups across your Lattice computers."],
        )
        if choice is None or choice == 8:
            return
        if choice == 0:
            _backup_overview_flow(stdscr)
        elif choice == 1:
            _setup_backup_flow(stdscr)
        elif choice == 2:
            _backup_now_flow(stdscr)
        elif choice == 3:
            _browse_backups_flow(stdscr)
        elif choice == 4:
            _manage_backup_targets_flow(stdscr)
        elif choice == 5:
            _pause_resume_backup_flow(stdscr)
        elif choice == 6:
            _backup_settings_flow(stdscr)
        elif choice == 7:
            _backup_history_flow(stdscr)


def _remove_worker_flow(stdscr) -> None:
    """Securely remove one Worker without leaving curses."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT hostname, ip, status FROM workers WHERE removed_at IS NULL ORDER BY hostname COLLATE NOCASE"
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        _control_result(stdscr, "REMOVE COMPUTER", ["No active Worker computers are registered."])
        return

    options = [f"{row[0]}   {row[1] or 'no address'}   {str(row[2] or 'unknown').upper()}" for row in rows]
    choice = _control_menu(
        stdscr, "REMOVE COMPUTER", options,
        intro=["Choose the Worker computer to securely remove from this Lattice fleet."],
    )
    if choice is None:
        return
    hostname, ip, _status = rows[choice]
    confirm = _control_menu(
        stdscr,
        "CONFIRM REMOVAL",
        ["Yes, Remove Computer", "Cancel"],
        intro=[
            f"Remove {hostname} ({ip or 'no address'})?",
            "Lattice will revoke its credentials, signed fleet membership, and file/shell authorization.",
            "Normal files on that computer are NOT deleted.",
        ],
    )
    if confirm != 0:
        return

    _flow_message(
        stdscr, "REMOVING COMPUTER",
        [f"Computer: {hostname}", "", "Securely revoking credentials and verifying the Worker..."],
        "Do not close Lattice while this operation is running.",
    )
    messages: List[str] = []
    try:
        from lattice.cli.commands.workers import remove_worker_safely
        result = remove_worker_safely(hostname, ask_confirmation=False, output=messages.append)
    except Exception as exc:
        result = 1
        messages.append(str(exc))
    if result == 0:
        lines = [f"✓ {hostname} was securely removed."] + messages[-4:]
        _control_result(stdscr, "COMPUTER REMOVED", lines)
    else:
        lines = [f"✗ Lattice did not complete removal of {hostname}.", "Nothing unsafe was forced."] + messages[-5:]
        _control_result(stdscr, "REMOVAL STOPPED", lines)


_SETTINGS_CATEGORIES = [
    ("General", [
        ("daemon.poll_interval", "Health Check Interval", "Normal cadence for Master health checks of Worker computers.", "seconds"),
        ("daemon.log_level", "Master Log Level", "Controls how much diagnostic detail the Master process writes to its logs.", ""),
    ]),
    ("Auto-Heal & Safety", [
        ("daemon.dry_run", "Auto-Heal Dry Run", "Global fail-safe that blocks automatic repair execution while still recording what Lattice would do.", ""),
    ]),
    ("File Access", [
        ("file_access.probe_interval_seconds", "File Probe Interval", "How often the mount manager rechecks and reconciles managed peer file access.", "seconds"),
        ("file_access.persistent_alert_seconds", "File Alert Delay", "How long a file-access failure must remain unresolved before Lattice creates an alert.", "seconds"),
        ("file_access.retry_initial_seconds", "Initial File Retry Delay", "Starting delay used by the exponential retry schedule after a file-access failure.", "seconds"),
        ("file_access.retry_max_seconds", "Maximum File Retry Delay", "Upper limit for the exponential delay between repeated file-access recovery attempts.", "seconds"),
    ]),
    ("Shell Access", [
        ("shell_access.reconnect_seconds", "Shell Recheck Interval", "How often the trusted-shell manager reconciles connections and retries unavailable peers.", "seconds"),
        ("shell_access.persistent_alert_seconds", "Shell Alert Delay", "How long trusted shell access must remain unavailable before Lattice creates an alert.", "seconds"),
    ]),
    ("Network & Health", [
        ("wire_format.connect_timeout_seconds", "Connection Timeout", "How long a Master-to-Worker HTTP connection may take to establish before that attempt fails.", "seconds"),
        ("wire_format.request_timeout_seconds", "Request I/O Timeout", "Timeout used for normal HTTP read, write, and connection-pool waits after connection setup.", "seconds"),
        ("wire_format.idle_timeout_seconds", "Idle Connection Timeout", "How long an unused pooled Worker HTTP connection may stay reusable before it is discarded.", "seconds"),
        ("wire_format.max_retry_attempts", "Network Attempt Limit", "Maximum total HTTP attempts for one Worker request, including the first attempt.", "attempts"),
    ]),
    ("Backup", [
        ("backup.schedule_hour", "Nightly Backup Hour", "Local clock hour used as the nightly backup boundary. Missed backups catch up automatically.", "hour"),
        ("backup.retention_daily", "Daily Versions", "Number of daily backup versions retained by the normal retention policy.", "versions"),
        ("backup.retention_weekly", "Weekly Versions", "Number of weekly backup versions retained by the normal retention policy.", "versions"),
        ("backup.retention_monthly", "Monthly Versions", "Number of monthly backup versions retained by the normal retention policy.", "versions"),
        ("backup.free_space_reserve_percent", "Free-Space Reserve", "Minimum target free-space percentage Lattice tries to preserve using normal retention only.", "percent"),
        ("backup.deep_verification_days", "Deep Verification", "How often each repository becomes due for a deeper data verification pass.", "days"),
        ("backup.persistent_alert_seconds", "Backup Alert Delay", "How long an unresolved backup problem persists before it becomes a durable alert.", "seconds"),
        ("backup.bandwidth_limit_kib", "Remote Backup Speed Limit", "Upload cap for normal remote backups. Zero means no saved cap; Back Up Now can temporarily use Full Speed.", "KiB/s"),
    ]),
    ("Advanced", [
        ("wire_format.retry_initial_backoff_ms", "Initial Network Backoff", "Starting wait between retryable Worker HTTP failures. Random jitter is added to avoid synchronized retries.", "ms"),
        ("wire_format.retry_max_backoff_ms", "Maximum Network Backoff", "Maximum wait used by the doubling network retry backoff.", "ms"),
        ("file_access.key_rotation_days", "File Key Rotation", "Age at which Lattice begins a coordinated rotation of dedicated file-access SSH credentials.", "days"),
        ("shell_access.key_rotation_days", "Shell Key Rotation", "Age at which Lattice begins a coordinated rotation of trusted-shell SSH credentials.", "days"),
    ]),
]


_SETTING_HELP = {
    "daemon.poll_interval": [
        "Normal cadence for Master health checks of Worker computers.",
        "Failed Workers can be checked less often because the health loop also uses per-Worker failure backoff.",
        "Lower values notice healthy-state changes sooner but perform checks more often.",
        "Default: 10 seconds. Minimum: 1 second. Applies after the Master service restarts.",
    ],
    "daemon.log_level": [
        "Controls the Master process log threshold: DEBUG, INFO, WARNING, or ERROR.",
        "DEBUG is most detailed; INFO is recommended for normal operation; WARNING and ERROR are quieter.",
        "Default: INFO. Applies immediately when the running Master accepts the configuration reload.",
    ],
    "daemon.dry_run": [
        "Safety switch for automatic healing. ON means Lattice records a proposed repair but does not execute it.",
        "OFF allows supported repair execution only when the separate auto-heal mode, per-Worker opt-in, and safety limits also allow it.",
        "The Worker repair endpoint independently checks this same fail-safe before executing a restart.",
        "Default: ON. Applies to the next healing decision; no service restart is required.",
    ],
    "file_access.probe_interval_seconds": [
        "Controls the mount-manager cycle that rechecks and reconciles managed peer file access.",
        "This is a detection/reconciliation interval; it does not control when alerts appear or how retry backoff grows.",
        "Default: 15 seconds. Minimum: 5 seconds. Applies on the mount manager's next cycle.",
    ],
    "file_access.persistent_alert_seconds": [
        "A file-access problem is timed from when the current problem began. Lattice alerts only after it remains unresolved for this long.",
        "Recovery retries continue during this delay, so a short outage can recover without creating a persistent alert.",
        "Default: 5 minutes (300 seconds). Minimum: 30 seconds. Applies immediately to unresolved problems.",
    ],
    "file_access.retry_initial_seconds": [
        "Starting retry delay after a file-access failure.",
        "The code doubles this delay for consecutive failures: initial, 2×, 4×, and so on, capped by Maximum File Retry Delay.",
        "Default: 2 seconds. Must be greater than 0. Applies to the next failed file-access attempt.",
    ],
    "file_access.retry_max_seconds": [
        "Caps the exponential file-access retry delay so retries never become farther apart than this value.",
        "This does not stop recovery; it limits how long Lattice waits between continued attempts during a long outage.",
        "Default: 5 minutes (300 seconds). Minimum: 10 seconds. Applies to the next failed file-access attempt.",
    ],
    "shell_access.reconnect_seconds": [
        "Controls the trusted-shell manager's reconciliation loop, including retries for unavailable peer connections.",
        "A lower value retries and reconciles more often; a higher value reduces retry frequency during outages.",
        "Default: 5 seconds. Minimum: 1 second. Applies after the current shell-manager cycle finishes.",
    ],
    "shell_access.persistent_alert_seconds": [
        "Lattice records when trusted shell access first becomes unavailable and alerts only if the outage lasts this long.",
        "Reconnect attempts continue while this timer is running.",
        "Default: 5 minutes (300 seconds). Minimum: 30 seconds. Applies immediately to unresolved shell problems.",
    ],
    "wire_format.connect_timeout_seconds": [
        "Maximum time allowed for the TCP/TLS connection phase of a Master-to-Worker HTTP attempt.",
        "A short value identifies unreachable LAN peers quickly; a value that is too short can reject unusually slow connection setup.",
        "Default: 2 seconds. Minimum: 1 second. Existing cached clients use the new value after the Master restarts.",
    ],
    "wire_format.request_timeout_seconds": [
        "Normal HTTP I/O timeout used for read, write, and connection-pool waits after connection setup.",
        "This is not the same as Connection Timeout, which covers only establishing the connection.",
        "Default: 30 seconds. Minimum: 1 second. Existing cached clients use the new value after the Master restarts.",
    ],
    "wire_format.idle_timeout_seconds": [
        "Controls how long an unused pooled Worker HTTP connection stays eligible for reuse.",
        "When the idle period expires, a later request opens a fresh connection instead of reusing the old one.",
        "Default: 60 seconds. Minimum: 1 second. Existing cached clients use the new value after the Master restarts.",
    ],
    "wire_format.max_retry_attempts": [
        "Maximum TOTAL attempts for one retryable Worker HTTP request, including the first attempt.",
        "For example, 3 means at most 3 attempts total, not 1 first attempt plus 3 additional retries.",
        "Only retryable transport failures, selected timeout/rate-limit responses, and server errors are retried.",
        "Default: 3 attempts. Minimum: 1. Existing cached clients use the new value after the Master restarts.",
    ],
    "backup.schedule_hour": [
        "Local clock hour that defines when a new nightly backup becomes due.",
        "Lattice does not lose a missed backup: a persistent timer and local job state catch it up after reboot or target/network recovery.",
        "Default: 2 (2:00 AM local time). Range: 0–23.",
    ],
    "backup.retention_daily": [
        "Number of daily restore points retained by normal Restic retention.",
        "Lattice also keeps weekly and monthly versions according to the settings below.",
        "Default: 30 daily versions. Retention never arbitrarily deletes extra protected snapshots just to chase free-space reserve.",
    ],
    "backup.retention_weekly": [
        "Number of weekly restore points retained in addition to daily versions.",
        "Default: 26 weekly versions (about six months).",
    ],
    "backup.retention_monthly": [
        "Number of monthly restore points retained for longer-term history.",
        "Default: 12 monthly versions (about one year).",
    ],
    "backup.free_space_reserve_percent": [
        "Minimum percentage of the backup target Lattice tries to keep free.",
        "If normal retention cannot restore this reserve safely, Lattice degrades/alerts instead of deleting arbitrary protected snapshots.",
        "Default: 20%. Range: 5–50%.",
    ],
    "backup.deep_verification_days": [
        "How often a repository becomes due for a deeper Restic data check in addition to normal post-backup verification.",
        "Default: every 7 days. Range: 1–90 days.",
    ],
    "backup.persistent_alert_seconds": [
        "How long a continuing backup problem must remain unresolved before Lattice creates a persistent backup alert.",
        "Short Wi-Fi interruptions can recover without immediate alert spam.",
        "Default: 24 hours (86400 seconds). Minimum: 5 minutes.",
    ],
    "backup.bandwidth_limit_kib": [
        "Upload cap used by normal remote Lattice backups, measured in KiB per second.",
        "0 means no saved cap yet. The recommended default will be chosen from real fleet LAN testing rather than guessed in advance.",
        "Back Up Now can choose Full Speed for one run without changing this saved setting.",
    ],
    "wire_format.retry_initial_backoff_ms": [
        "Starting delay between retryable Worker HTTP failures.",
        "Each later retry doubles the backoff and adds about ±25% random jitter, up to Maximum Network Backoff.",
        "Default: 100 ms. Minimum: 1 ms. Existing cached clients use the new value after the Master restarts.",
    ],
    "wire_format.retry_max_backoff_ms": [
        "Caps the doubling network retry backoff between retryable Worker HTTP attempts.",
        "The random jitter is applied to the current backoff before the next doubled value is capped here.",
        "Default: 2 seconds (2000 ms). Minimum: 1 ms. Existing cached clients use the new value after the Master restarts.",
    ],
    "file_access.key_rotation_days": [
        "When either dedicated file-access SSH key reaches this age, Lattice can stage a new generation.",
        "Rotation is coordinated and uses an overlap/promotion process; the current key is not simply deleted when the age is reached.",
        "Default: 90 days. Minimum: 1 day. Checked during file-access reconciliation.",
    ],
    "shell_access.key_rotation_days": [
        "When either trusted-shell SSH key reaches this age, Lattice can stage a new generation.",
        "Rotation is coordinated and promoted only through the signed fleet rotation workflow rather than replacing keys in one step.",
        "Default: 90 days. Minimum: 1 day. Checked during shell-access reconciliation.",
    ],
}


def _format_setting_value(value, unit: str) -> str:
    """Format configuration values for operators without changing stored units."""
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if unit == "seconds":
        numeric = float(value)
        if numeric >= 60 and numeric.is_integer() and int(numeric) % 60 == 0:
            minutes = int(numeric) // 60
            return f"{minutes} minute" + ("s" if minutes != 1 else "")
        shown = f"{numeric:g}"
        return f"{shown} seconds"
    if unit == "ms":
        numeric = float(value)
        if numeric >= 1000 and numeric.is_integer() and int(numeric) % 1000 == 0:
            seconds = int(numeric) // 1000
            return f"{seconds} second" + ("s" if seconds != 1 else "")
        return f"{numeric:g} ms"
    if unit == "days":
        numeric = float(value)
        shown = f"{numeric:g}"
        return f"{shown} day" + ("s" if numeric != 1 else "")
    if unit == "attempts":
        return f"{value} attempt" + ("s" if int(value) != 1 else "")
    if unit == "hour":
        return f"{int(value):02d}:00 local"
    if unit == "versions":
        return f"{value} version" + ("s" if int(value) != 1 else "")
    if unit == "percent":
        return f"{value}%"
    if unit == "KiB/s":
        return "No cap" if int(value) == 0 else f"{value} KiB/s"
    return str(value)


def _setting_help(path: str, config) -> List[str]:
    lines = list(_SETTING_HELP.get(path, []))
    try:
        current = _nested_value(config, path)
        unit = next(
            item[3]
            for _category, items in _SETTINGS_CATEGORIES
            for item in items
            if item[0] == path
        )
        lines.insert(0, f"Current: {_format_setting_value(current, unit)}")
    except (AttributeError, StopIteration, TypeError, ValueError):
        pass
    return lines


def _setting_apply_note(path: str) -> str:
    if path == "daemon.poll_interval":
        return "The saved health-check interval is used after the Master service restarts."
    if path.startswith("wire_format."):
        return "Existing cached Worker HTTP clients use this network setting after the Master service restarts."
    if path == "daemon.log_level":
        return "The running Master applies the new log level when it accepts the configuration reload."
    if path.startswith("file_access."):
        return "The file-access manager reads this setting during its ongoing reconciliation/recovery work."
    if path.startswith("shell_access."):
        return "The shell-access manager reads this setting during its ongoing reconciliation/recovery work."
    if path.startswith("backup."):
        return "The Master will sign and distribute this Backup policy; source computers use it after their next backup-configuration reconciliation."
    if path == "daemon.dry_run":
        return "The new dry-run safety state is checked on the next automatic-heal decision."
    return "The setting was saved."


def _nested_value(config, path: str):
    value = config
    for part in path.split('.'):
        value = getattr(value, part)
    return value


def _validated_config_update(config, path: str, raw_value: str):
    """Return a fully validated config with one scalar setting changed."""
    current = _nested_value(config, path)
    if isinstance(current, bool):
        parsed = raw_value.strip().lower() in {"true", "1", "yes", "on"}
    elif isinstance(current, int) and not isinstance(current, bool):
        parsed = int(raw_value.strip())
    elif isinstance(current, float):
        parsed = float(raw_value.strip())
    else:
        parsed = raw_value.strip()
    payload = config.model_dump()
    parts = path.split('.')
    target = payload
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = parsed
    return LatticeConfig.model_validate(payload)



def _autoheal_mode_value() -> str:
    """Return the effective global auto-heal mode."""
    from lattice.core.config import get_config_value

    return (
        "automatic"
        if get_config_value("autoheal.mode") == "automatic"
        else "alert_only"
    )


def _autoheal_worker_rows() -> List[tuple[int, str, bool]]:
    """Return active Workers and their independent auto-heal opt-in state."""
    from lattice.core.config import get_config_value

    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, hostname
            FROM workers
            WHERE removed_at IS NULL
            ORDER BY hostname COLLATE NOCASE
            """
        ).fetchall()
    finally:
        conn.close()

    result = []
    for row in rows:
        worker_id = int(row[0])
        hostname = str(row[1])
        enabled = (
            get_config_value(f"autoheal.enabled.{worker_id}") == "true"
        )
        result.append((worker_id, hostname, enabled))
    return result


def _set_autoheal_mode(mode: str) -> None:
    """Set only the global auto-heal execution mode."""
    from lattice.core.config import set_config_value

    if mode not in {"alert_only", "automatic"}:
        raise ValueError(f"Unsupported auto-heal mode: {mode}")
    set_config_value("autoheal.mode", mode)


def _set_worker_autoheal(worker_id: int, enabled: bool) -> None:
    """Set auto-heal opt-in for exactly one Worker."""
    from lattice.core.config import set_config_value

    set_config_value(
        f"autoheal.enabled.{int(worker_id)}",
        "true" if enabled else "false",
    )


def _autoheal_settings_flow(stdscr) -> None:
    """Complete Auto-Heal & Safety controls inside the TUI."""
    while True:
        try:
            config = load_config()
            mode = _autoheal_mode_value()
            workers = _autoheal_worker_rows()
        except Exception as exc:
            _control_result(
                stdscr,
                "AUTO-HEAL SETTINGS ERROR",
                [f"Could not load Auto-Heal settings: {exc}"],
            )
            return

        mode_label = (
            "AUTOMATIC" if mode == "automatic" else "ALERT ONLY"
        )
        dry_run = bool(config.daemon.dry_run)

        labels = [
            f"{'Auto-Heal Mode':<30} {mode_label}",
            f"{'Auto-Heal Dry Run':<30} {'ON' if dry_run else 'OFF'}",
        ]
        help_texts = [
            [
                f"Current: {mode_label}",
                "ALERT ONLY detects and reports problems but does not execute repairs.",
                "AUTOMATIC permits supported repairs only for Workers individually opted in below.",
                "Dry Run and all normal safety limits still apply.",
            ],
            _setting_help("daemon.dry_run", config),
        ]

        for _worker_id, hostname, enabled in workers:
            labels.append(
                f"{(hostname + ' Auto-Heal'):<30} "
                f"{'ON' if enabled else 'OFF'}"
            )
            help_texts.append([
                f"Current: {'ON' if enabled else 'OFF'}",
                f"Controls automatic healing for {hostname} only.",
                "Changing this Worker does not enable or disable any other Worker.",
                f"Global mode is currently {mode_label}; "
                f"Dry Run is {'ON' if dry_run else 'OFF'}.",
            ])

        choice = _control_menu(
            stdscr,
            "AUTO-HEAL & SAFETY",
            labels,
            help_texts=help_texts,
        )
        if choice is None:
            return

        if choice == 0:
            mode_choice = _control_menu(
                stdscr,
                "AUTO-HEAL MODE",
                ["AUTOMATIC", "ALERT ONLY", "Cancel"],
                intro=[
                    f"Current: {mode_label}",
                    "AUTOMATIC allows supported repairs only for Workers "
                    "whose individual Auto-Heal switch is ON.",
                    "Dry Run remains a separate global safety switch.",
                ],
            )
            if mode_choice is None or mode_choice == 2:
                continue

            new_mode = (
                "automatic" if mode_choice == 0 else "alert_only"
            )
            try:
                _set_autoheal_mode(new_mode)
            except Exception as exc:
                _control_result(
                    stdscr,
                    "SETTING NOT CHANGED",
                    ["✗ Auto-Heal Mode was not changed.", str(exc)],
                )
                continue

            _control_result(
                stdscr,
                "SETTING SAVED",
                [
                    "✓ Auto-Heal Mode saved as "
                    + (
                        "AUTOMATIC"
                        if new_mode == "automatic"
                        else "ALERT ONLY"
                    )
                    + ".",
                    "Only Workers individually set to ON are eligible "
                    "for automatic healing.",
                    "Dry Run and the normal repair safety limits remain active.",
                ],
            )
            continue

        if choice == 1:
            dry_choice = _control_menu(
                stdscr,
                "AUTO-HEAL DRY RUN",
                ["ON", "OFF", "Cancel"],
                intro=[
                    "Global fail-safe for automatic repair execution.",
                    f"Current: {'ON' if dry_run else 'OFF'}",
                ],
            )
            if dry_choice is None or dry_choice == 2:
                continue

            raw = "true" if dry_choice == 0 else "false"
            try:
                updated = _validated_config_update(
                    config, "daemon.dry_run", raw
                )
                save_config(updated)
                reloaded = reload_daemon()
            except Exception as exc:
                _control_result(
                    stdscr,
                    "SETTING NOT CHANGED",
                    ["✗ Auto-Heal Dry Run was not changed.", str(exc)],
                )
                continue

            new_value = bool(updated.daemon.dry_run)
            _control_result(
                stdscr,
                "SETTING SAVED",
                [
                    "✓ Auto-Heal Dry Run saved as "
                    f"{'ON' if new_value else 'OFF'}.",
                    (
                        "✓ Running Master acknowledged the configuration reload."
                        if reloaded
                        else "⚠ Setting saved, but the running Master did not "
                             "confirm the configuration reload."
                    ),
                    _setting_apply_note("daemon.dry_run"),
                ],
            )
            continue

        worker_index = choice - 2
        if worker_index < 0 or worker_index >= len(workers):
            continue

        worker_id, hostname, enabled = workers[worker_index]
        worker_choice = _control_menu(
            stdscr,
            f"AUTO-HEAL — {hostname}",
            ["ON", "OFF", "Cancel"],
            intro=[
                f"Current: {'ON' if enabled else 'OFF'}",
                f"This changes automatic healing for {hostname} only.",
                f"Global mode: {mode_label}",
                f"Dry Run: {'ON' if dry_run else 'OFF'}",
            ],
        )
        if worker_choice is None or worker_choice == 2:
            continue

        new_enabled = worker_choice == 0
        try:
            _set_worker_autoheal(worker_id, new_enabled)
        except Exception as exc:
            _control_result(
                stdscr,
                "SETTING NOT CHANGED",
                [f"✗ Auto-Heal for {hostname} was not changed.", str(exc)],
            )
            continue

        _control_result(
            stdscr,
            "SETTING SAVED",
            [
                f"✓ {hostname} Auto-Heal saved as "
                f"{'ON' if new_enabled else 'OFF'}.",
                "No other Worker's Auto-Heal setting was changed.",
                f"Global mode remains {mode_label}; "
                f"Dry Run remains {'ON' if dry_run else 'OFF'}.",
            ],
        )



def _settings_flow(stdscr) -> None:
    """Friendly validated settings editor; secrets/provisioning values stay hidden."""
    while True:
        categories = [name for name, _items in _SETTINGS_CATEGORIES]
        category_index = _control_menu(
            stdscr, "SETTINGS", categories,
            intro=[
                "Choose a settings area.",
                "Credentials, secrets, service ports, and provisioning-only values are intentionally protected here.",
            ],
        )
        if category_index is None:
            return
        category_name, items = _SETTINGS_CATEGORIES[category_index]
        if category_name == "Auto-Heal & Safety":
            _autoheal_settings_flow(stdscr)
            continue
        while True:
            try:
                config = load_config()
            except Exception as exc:
                _control_result(stdscr, "SETTINGS ERROR", [f"Could not load Lattice settings: {exc}"])
                return
            labels = []
            help_texts = []
            for path, label, _description, unit in items:
                value = _nested_value(config, path)
                shown = _format_setting_value(value, unit)
                labels.append(f"{label:<30} {shown}")
                help_texts.append(_setting_help(path, config))
            item_index = _control_menu(
                stdscr,
                category_name.upper(),
                labels,
                help_texts=help_texts,
            )
            if item_index is None:
                break
            path, label, description, unit = items[item_index]
            current = _nested_value(config, path)
            if isinstance(current, bool):
                value_choice = _control_menu(
                    stdscr, label.upper(), ["ON", "OFF", "Cancel"],
                    intro=[description, f"Current: {'ON' if current else 'OFF'}"],
                )
                if value_choice is None or value_choice == 2:
                    continue
                raw = "true" if value_choice == 0 else "false"
            elif path == "daemon.log_level":
                choices = ["DEBUG", "INFO", "WARNING", "ERROR", "Cancel"]
                value_choice = _control_menu(
                    stdscr, label.upper(), choices,
                    intro=[description, f"Current: {current}"],
                )
                if value_choice is None or value_choice == len(choices) - 1:
                    continue
                raw = choices[value_choice]
            else:
                raw_input = _control_text_input(
                    stdscr, label.upper(),
                    f"{description}\nCurrent: {current}{(' ' + unit) if unit else ''}\nEnter the new value:",
                )
                if raw_input is None or not raw_input.strip():
                    continue
                raw = raw_input.strip()
            try:
                updated = _validated_config_update(config, path, raw)
                save_config(updated)
                reloaded = reload_daemon()
            except Exception as exc:
                _control_result(stdscr, "SETTING NOT CHANGED", [f"✗ {label} was not changed.", str(exc)])
                continue
            new_value = _nested_value(updated, path)
            lines = [f"✓ {label} saved as {_format_setting_value(new_value, unit)}."]
            lines.append("✓ Running Master acknowledged the configuration reload." if reloaded else "⚠ Setting saved, but the running Master did not confirm the configuration reload.")
            lines.append(_setting_apply_note(path))
            _control_result(stdscr, "SETTING SAVED", lines)


def _request_worker_rechecks(hostnames: List[str]) -> Dict[str, int]:
    """Request real immediate checks and return each Worker's prior health event id."""
    from lattice.core.config import set_config_value
    from lattice.core.events import log_event
    conn = get_db_connection()
    try:
        baselines: Dict[str, int] = {}
        for hostname in hostnames:
            row = conn.execute(
                "SELECT id FROM workers WHERE hostname=? AND removed_at IS NULL", (hostname,)
            ).fetchone()
            if row is None:
                continue
            worker_id = int(row[0])
            old = conn.execute(
                "SELECT COALESCE(MAX(id), 0) FROM events WHERE worker_id=? AND type='health_check'",
                (worker_id,),
            ).fetchone()
            baselines[hostname] = int(old[0] or 0)
            set_config_value(f"health.recheck.{worker_id}", "true")
            log_event(worker_id, "recheck_triggered", "info", f"Manual TUI health check requested for {hostname}")
        return baselines
    finally:
        conn.close()


def _wait_for_worker_checks(stdscr, baselines: Dict[str, int], timeout_seconds: float = 20.0) -> Dict[str, Dict[str, str]]:
    deadline = time.monotonic() + timeout_seconds
    pending = dict(baselines)
    results: Dict[str, Dict[str, str]] = {}
    while pending and time.monotonic() < deadline:
        conn = get_db_connection()
        try:
            for hostname, baseline in list(pending.items()):
                row = conn.execute(
                    """
                    SELECT e.id, e.severity, e.message
                    FROM events e JOIN workers w ON w.id=e.worker_id
                    WHERE w.hostname=? AND e.type='health_check' AND e.id>?
                    ORDER BY e.id DESC LIMIT 1
                    """,
                    (hostname, baseline),
                ).fetchone()
                if row is not None:
                    results[hostname] = {"severity": str(row[1]), "message": str(row[2])}
                    pending.pop(hostname, None)
        finally:
            conn.close()
        if pending:
            _flow_message(
                stdscr, "HEALTH CHECK",
                ["Running fresh independent health checks...", "", *[f"◌ {name}" for name in pending]],
                "Lattice is waiting for the normal Master health engine to finish.",
            )
            time.sleep(0.25)
    for hostname in pending:
        results[hostname] = {"severity": "timeout", "message": "No fresh health-check result arrived before the TUI timeout."}
    return results


def _master_health_lines(status_loader=None) -> List[str]:
    from lattice.core import self_check
    checks = []
    try:
        self_check.check_db()
        checks.append(("Database", True, "READY"))
    except Exception as exc:
        checks.append(("Database", False, str(exc)))
    try:
        self_check.check_socket()
        checks.append(("Master Socket", True, "READY"))
    except Exception as exc:
        checks.append(("Master Socket", False, str(exc)))
    try:
        size, severity = self_check.audit_log_capacity()
        checks.append(("Audit Log", severity is None, "READY" if severity is None else severity.upper()))
    except Exception as exc:
        checks.append(("Audit Log", False, str(exc)))
    if status_loader is not None:
        try:
            snap = status_loader()
            network_ok = str(snap.health.get("network", {}).get("state")) == "healthy"
            checks.append(("Network", network_ok, str(snap.health.get("network", {}).get("label") or "UNKNOWN").upper()))
            checks.append(("Daemon", snap.daemon_status == "running", snap.daemon_status.upper()))
        except Exception as exc:
            checks.append(("Runtime Status", False, str(exc)))
    lines = [f"{'✓' if ok else '✗'} {label:<16} {detail}" for label, ok, detail in checks]
    lines.append("")
    lines.append("Overall: ✓ HEALTHY" if all(ok for _label, ok, _detail in checks) else "Overall: ✗ NEEDS ATTENTION")
    return lines


def _worker_health_lines(hostname: str, result: Dict[str, str], status_loader=None) -> List[str]:
    fresh_status = None
    if status_loader is not None:
        try:
            fresh_status = status_loader()
        except Exception:
            fresh_status = None
    worker = None
    access = None
    if fresh_status is not None:
        worker = next((w for w in fresh_status.workers if str(w.get("hostname")) == hostname), None)
        access = next((a for a in fresh_status.health.get("node_access", []) if str(a.get("hostname")) == hostname), None)
    severity = str(result.get("severity") or "timeout").lower()
    check_ok = severity in {"ok", "info", "success"}
    lines = [f"{'✓' if check_ok else '✗'} Fresh Check       {result.get('message', 'unknown')}"]
    if worker is not None:
        lines.append(f"{'✓' if str(worker.get('status')).lower() == 'healthy' else '✗'} Worker State      {str(worker.get('status') or 'unknown').upper()}")
        lines.append(f"{'✓' if int(worker.get('services_fail') or 0) == 0 else '✗'} Services          {int(worker.get('services_fail') or 0)} failed")
    if access is not None:
        for label, key, value_key in [
            ("File / Mount", "file_ok", "file"),
            ("Shell", "shell_ok", "shell"),
            ("Admin", "admin_ok", "admin"),
        ]:
            ok = bool(access.get(key))
            lines.append(f"{'✓' if ok else '✗'} {label:<17} {str(access.get(value_key) or 'UNKNOWN')}")
    overall = check_ok and (worker is None or str(worker.get("status")).lower() == "healthy") and (
        access is None or all(bool(access.get(k)) for k in ("file_ok", "shell_ok", "admin_ok"))
    )
    lines.append("")
    lines.append("Overall: ✓ HEALTHY" if overall else "Overall: ✗ NEEDS ATTENTION")
    return lines


def _health_check_flow(stdscr, current: LatticeStatus, status_loader=None) -> None:
    """Run real Master/Worker checks and keep all results inside curses."""
    while True:
        workers = [str(w.get("hostname")) for w in current.workers if w.get("hostname")]
        options = ["Entire Fleet", "Master"] + workers + ["Back"]
        choice = _control_menu(stdscr, "HEALTH CHECK", options, intro=["Choose what Lattice should check now."])
        if choice is None or choice == len(options) - 1:
            return
        if choice == 1:
            _flow_message(stdscr, "HEALTH CHECK", ["Checking the Master now..."])
            _control_result(stdscr, "MASTER HEALTH CHECK", _master_health_lines(status_loader))
            continue
        targets = workers if choice == 0 else [workers[choice - 2]]
        if not targets:
            _control_result(stdscr, "HEALTH CHECK", ["No Worker computers are registered."])
            continue
        try:
            baselines = _request_worker_rechecks(targets)
            results = _wait_for_worker_checks(stdscr, baselines)
        except Exception as exc:
            _control_result(stdscr, "HEALTH CHECK FAILED", [str(exc)])
            continue
        if choice == 0:
            lines = _master_health_lines(status_loader)
            master_ok = "Overall: ✓ HEALTHY" in lines
            lines.extend(["", "WORKERS"])
            healthy = 1 if master_ok else 0
            fresh_snapshot = None
            if status_loader is not None:
                try:
                    fresh_snapshot = status_loader()
                except Exception:
                    fresh_snapshot = None
            snapshot_loader = (lambda: fresh_snapshot) if fresh_snapshot is not None else None
            for hostname in targets:
                worker_lines = _worker_health_lines(
                    hostname, results.get(hostname, {}), snapshot_loader
                )
                ok = "Overall: ✓ HEALTHY" in worker_lines
                healthy += int(ok)
                lines.append(f"{'✓' if ok else '✗'} {hostname:<20} {'HEALTHY' if ok else 'NEEDS ATTENTION'}")
            lines.extend(["", f"{healthy}/{1 + len(targets)} computers passed this health check."])
            _control_result(stdscr, "FLEET HEALTH CHECK", lines)
        else:
            hostname = targets[0]
            _control_result(stdscr, f"HEALTH CHECK — {hostname}", _worker_health_lines(hostname, results[hostname], status_loader))
        if status_loader is not None:
            try:
                current = status_loader()
            except Exception:
                pass


def _repair_label(candidate) -> str:
    return f"{candidate.hostname:<18} {candidate.category:<14} {candidate.action}"


def _run_repair(stdscr, controller, candidate) -> None:
    if candidate.requires_confirmation:
        choice = _control_menu(
            stdscr, "CONFIRM REPAIR", ["Repair Now", "Cancel"],
            intro=[candidate.hostname, candidate.problem, "", candidate.action,
                   "Lattice will audit the request and independently verify the result."],
        )
        if choice != 0:
            return
    _flow_message(stdscr, "REPAIRING", [candidate.hostname, candidate.action, "", "Lattice is performing one bounded repair and verifying it..."])
    result = controller.execute(candidate)
    title = "REPAIR VERIFIED" if result.success and result.verified else "REPAIR NEEDS ATTENTION"
    lines = [
        ("✓ " if result.success and result.verified else "✗ ") + result.summary,
        f"Computer: {candidate.hostname}",
        f"Action: {candidate.action}",
    ]
    if result.error:
        lines.extend(["", f"Reason: {result.error}"])
    _control_result(stdscr, title, lines)


def _repair_candidates_menu(stdscr, title: str, candidates: List[Any]) -> None:
    if not candidates:
        _control_result(stdscr, title, ["✓ No current Lattice problem needs this repair."])
        return
    controller = None
    while True:
        options = [_repair_label(item) for item in candidates] + ["Back"]
        choice = _control_menu(stdscr, title, options,
            intro=["Choose one supported repair. Lattice never runs arbitrary system commands here."])
        if choice is None or choice == len(candidates):
            return
        if controller is None:
            from lattice.repair import RepairController
            controller = RepairController()
        _run_repair(stdscr, controller, candidates[choice])


def _fix_recommended_flow(stdscr, current: LatticeStatus, status_loader=None) -> None:
    from lattice.repair.controller import manual_actions_for
    if status_loader is not None:
        try:
            current = status_loader()
        except Exception:
            pass
    candidates = manual_actions_for(current)
    if not candidates:
        _control_result(stdscr, "FIX RECOMMENDED", ["✓ No problems currently require repair.", "", "Fleet health is currently clean."])
        return
    lines = ["Lattice found these supported repairs:", ""]
    lines.extend(f"• {item.hostname}: {item.action}" for item in candidates)
    choice = _control_menu(stdscr, "FIX RECOMMENDED", ["Fix Safe Problems", "Review One by One", "Run Fresh Health Check", "Back"], intro=lines)
    if choice == 0:
        from lattice.repair import RepairController
        controller = RepairController()
        for candidate in candidates:
            _run_repair(stdscr, controller, candidate)
    elif choice == 1:
        _repair_candidates_menu(stdscr, "FIX RECOMMENDED", candidates)
    elif choice == 2:
        _health_check_flow(stdscr, current, status_loader)


def _fix_computer_flow(stdscr, current: LatticeStatus, status_loader=None) -> None:
    from lattice.repair.controller import manual_actions_for
    names = [current.master_hostname] + [str(w.get("hostname")) for w in current.workers if w.get("hostname")]
    choice = _control_menu(stdscr, "FIX A COMPUTER", names + ["Back"], intro=["Choose a computer. Options are based on its current Lattice evidence."])
    if choice is None or choice == len(names):
        return
    hostname = names[choice]
    if status_loader is not None:
        try:
            current = status_loader()
        except Exception:
            pass
    candidates = manual_actions_for(current, hostname)
    options = ["Fix Recommended", "Run Fresh Health Check"]
    if candidates:
        options.extend(_repair_label(item) for item in candidates)
    options.append("Back")
    action = _control_menu(stdscr, f"FIX — {hostname}", options,
        intro=["Only safe Lattice-owned actions are shown."])
    if action is None or action == len(options) - 1:
        return
    if action == 0:
        _repair_candidates_menu(stdscr, f"FIX — {hostname}", candidates)
    elif action == 1:
        _health_check_flow(stdscr, current, status_loader)
    else:
        _repair_candidates_menu(stdscr, f"FIX — {hostname}", [candidates[action - 2]])


def _fix_autoheal_reasons(stdscr, current: LatticeStatus) -> None:
    workers = [str(w.get("hostname")) for w in current.workers if w.get("hostname")]
    choice = _control_menu(stdscr, "WHY WASN'T THIS AUTO-FIXED?", workers + ["Back"], intro=["Lattice shows real current safety/policy reasons; it does not guess."])
    if choice is None or choice == len(workers):
        return
    from lattice.repair import RepairController
    hostname = workers[choice]
    _control_result(stdscr, f"AUTO-HEAL — {hostname}", RepairController().autoheal_reasons(hostname))


def _fix_history(stdscr) -> None:
    from lattice.repair import RepairController
    rows = RepairController().history()
    if not rows:
        _control_result(stdscr, "REPAIR HISTORY", ["No audited manual Lattice repairs have been recorded yet."])
        return
    lines = []
    for row in rows:
        detail = f"{row['timestamp'][-14:-6]}  {row['hostname']:<18} {row['action']} → {row['result'].upper()}"
        lines.append(detail)
        if row["error"]:
            lines.append(f"  {row['error']}")
    _control_result(stdscr, "REPAIR HISTORY", lines)


def _fix_flow(stdscr, current: LatticeStatus, status_loader=None) -> None:
    from lattice.repair.controller import manual_actions_for
    while True:
        choice = _control_menu(stdscr, "FIX LATTICE", [
            "Fix Recommended", "Fix a Computer", "Fix File Access", "Fix Trusted Shell",
            "Fix Network", "Restart Lattice", "Why Wasn't This Auto-Fixed?", "Repair History", "Back",
        ], intro=["Diagnose → choose one supported repair → audit → verify.", "Reset Lattice remains a separate destructive operation."])
        if choice is None or choice == 8:
            return
        if status_loader is not None:
            try:
                current = status_loader()
            except Exception:
                pass
        candidates = manual_actions_for(current)
        if choice == 0:
            _fix_recommended_flow(stdscr, current, status_loader)
        elif choice == 1:
            _fix_computer_flow(stdscr, current, status_loader)
        elif choice == 2:
            _repair_candidates_menu(stdscr, "FIX FILE ACCESS", [c for c in candidates if c.category == "File Access"])
        elif choice == 3:
            _repair_candidates_menu(stdscr, "FIX TRUSTED SHELL", [c for c in candidates if c.category == "Trusted Shell"])
        elif choice == 4:
            _repair_candidates_menu(stdscr, "FIX NETWORK", [c for c in candidates if c.category == "Network"])
        elif choice == 5:
            _repair_candidates_menu(stdscr, "RESTART LATTICE", [c for c in candidates if c.id in {"restart_master", "restart_worker"}])
        elif choice == 6:
            _fix_autoheal_reasons(stdscr, current)
        elif choice == 7:
            _fix_history(stdscr)


def _reset_lattice_flow(stdscr) -> bool:
    """Authenticate and run the existing fail-closed wipe operation inside curses."""
    conn = get_db_connection()
    try:
        hostnames = [row[0] for row in conn.execute(
            "SELECT hostname FROM workers WHERE removed_at IS NULL ORDER BY hostname COLLATE NOCASE"
        ).fetchall()]
    finally:
        conn.close()
    intro = [
        "This resets the current Lattice fleet and runtime state.",
        "Every Worker is securely revoked before Master fleet state is cleared.",
        "The installed Master role and host/network setup remain in place.",
        "Normal files on your computers are NOT deleted.",
    ]
    if hostnames:
        intro.extend(["", "Computers to revoke:", *[f"• {name}" for name in hostnames]])
    choice = _control_menu(stdscr, "RESET LATTICE", ["Continue", "Cancel"], intro=intro)
    if choice != 0:
        return False
    config = load_config()
    master_key = str(config.master.master_key or "")
    if not master_key:
        _control_result(stdscr, "RESET BLOCKED", ["No Master key is configured. Lattice refused to reset."])
        return False
    entered = _control_text_input(stdscr, "RESET LATTICE", "Enter the Master key:", secret=True)
    if entered is None:
        return False
    import hmac
    if not hmac.compare_digest(entered, master_key):
        _control_result(stdscr, "RESET BLOCKED", ["✗ Invalid Master key. Nothing was changed."])
        return False
    confirmation = _control_text_input(
        stdscr, "FINAL RESET CONFIRMATION",
        "Type RESET LATTICE exactly to revoke the fleet and clear Lattice state:",
    )
    if confirmation != "RESET LATTICE":
        if confirmation is not None:
            _control_result(stdscr, "RESET CANCELLED", ["Confirmation did not match. Nothing was changed."])
        return False
    _flow_message(
        stdscr, "RESETTING LATTICE",
        ["Securely revoking every Worker and clearing Master fleet state..."],
        "Lattice will stop safely if any Worker revocation cannot be verified.",
    )
    messages: List[str] = []
    try:
        from lattice.cli.commands.wipe import perform_wipe
        result = perform_wipe(output=messages.append)
    except Exception as exc:
        result = 1
        messages.append(str(exc))
    if result == 0:
        _control_result(stdscr, "LATTICE RESET COMPLETE", ["✓ Every Worker was revoked and Lattice state was removed."] + messages[-5:])
        return True
    _control_result(stdscr, "RESET STOPPED SAFELY", ["✗ Lattice did not complete the reset.", "Remaining state was preserved where required for safety."] + messages[-6:])
    return False



def _human_bytes(value: object) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "unknown"
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if abs(size) < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return "unknown"


def _worker_backup_label(job: dict) -> tuple[str, bool]:
    if not bool(job.get("enabled", 1)):
        return "OFF", False
    if bool(job.get("paused", 0)):
        return "PAUSED", False
    obs = job.get("observation") or {}
    state = str(obs.get("state") or "never_backed_up")
    if state == "healthy":
        return "HEALTHY", True
    if state == "running":
        return "RUNNING", True
    if state == "never_backed_up":
        return "READY", True
    return "DEGRADED", False


def _worker_backup_flow(stdscr, current: LatticeStatus, status_loader) -> None:
    while True:
        worker = current.health.get("worker", {})
        jobs = list(worker.get("backup_jobs", []))
        targets = list(worker.get("hosted_targets", []))
        lines = []
        if not jobs:
            lines.append("This computer does not currently have a Backup job configured.")
        for job in jobs:
            label, _ok = _worker_backup_label(job)
            obs = job.get("observation") or {}
            lines.extend([
                f"Destination: {job.get('friendly_name') or 'unknown'}",
                f"Status: {label}",
                f"Source: {job.get('source_path') or 'unknown'}",
                f"Last result: {obs.get('last_result') or 'none yet'}",
                f"Last success: {obs.get('last_success_at') or 'none yet'}",
                f"Failure streak: {obs.get('failure_streak', 0)}",
                f"Deep verification: {obs.get('last_deep_verification_at') or 'not yet'}",
                "",
            ])
        if targets:
            lines.append("BACKUP STORAGE HOSTED BY THIS COMPUTER")
            for target in targets:
                lines.extend([
                    f"Target: {target.get('friendly_name') or target.get('target_uuid')}",
                    f"Status: {str(target.get('health') or 'unknown').upper()}",
                    f"Mounted: {'YES' if target.get('present') else 'NO'}",
                    f"Mountpoint: {target.get('mountpoint') or 'not mounted'}",
                    f"Capacity: {_human_bytes(target.get('total_bytes'))}",
                    f"Free: {_human_bytes(target.get('free_bytes'))}",
                    "",
                ])

        options = []
        actions = []
        for job in jobs:
            target_name = str(job.get("friendly_name") or "Backup")
            if bool(job.get("enabled", 1)) and not bool(job.get("paused", 0)):
                options.append(f"Back Up Now — {target_name}")
                actions.append(("run", job))
            options.append(f"Browse / Restore — {target_name}")
            actions.append(("browse", job))
        options.append("Back")
        actions.append(("back", None))

        choice = _control_menu(
            stdscr, "WORKER BACKUP", options,
            intro=lines,
        )
        if choice is None:
            return
        action, selected_job = actions[choice]
        if action == "back":
            return
        assert isinstance(selected_job, dict)

        if action == "browse":
            _browse_backup_job_flow(
                stdscr,
                {
                    "job_uuid": str(selected_job.get("job_uuid") or ""),
                    "source_hostname": str(worker.get("hostname") or "this computer"),
                    "target_name": str(selected_job.get("friendly_name") or "Backup"),
                },
            )
            continue

        job_uuid = str(selected_job.get("job_uuid") or "")
        try:
            result = _backup_control("run-now", job_uuid)
            message = str(
                result.get("message")
                or result.get("status")
                or "Backup request accepted."
            )
        except RuntimeError as exc:
            message = f"Backup request was refused: {exc}"
        _flow_message(stdscr, "WORKER BACKUP", [message], "Press any key to return.")
        _modal_getch(stdscr)
        if status_loader is not None:
            try:
                current = status_loader()
            except Exception:
                pass


def _care_status_lines(care: dict) -> List[str]:
    status = str(care.get("status") or "stale").upper()
    lines = [
        f"Status: {status}",
        f"Last run: {care.get('last_run_at') or 'not yet'}",
        f"Reclaimed: {_human_bytes(care.get('bytes_reclaimed') or 0)}",
        f"Attention findings: {int(care.get('attention_count') or 0)}",
        f"Critical findings: {int(care.get('critical_count') or 0)}",
    ]
    if care.get("deferred_reason"):
        lines.append(f"Deferred: {care.get('deferred_reason')}")
    findings = list(care.get("findings") or [])
    if findings:
        lines.extend(["", "FINDINGS"])
        for item in findings[:12]:
            lines.append(
                f"{str(item.get('severity') or 'attention').upper()}: "
                f"{str(item.get('subject') or item.get('code') or 'Daily Care finding')}"
            )
            detail = str(item.get("detail") or "")
            if detail:
                lines.append(f"  {detail[:100]}")
    else:
        lines.extend(["", "No open Daily Care findings."])
    lines.extend([
        "",
        "Protected: /home, /root, Lattice peer mounts, Backup repositories.",
        "Daily Care never reboots automatically or installs ordinary updates.",
    ])
    return lines


def _run_local_care(stdscr) -> None:
    choice = _control_menu(
        stdscr,
        "RUN DAILY CARE NOW",
        ["Run Daily Care Now", "Cancel"],
        intro=[
            "Runs the same conservative local policy used by the daily timer.",
            "Home folders and saved browser/login data are outside the cleanup boundary.",
        ],
    )
    if choice != 0:
        return
    _flow_message(stdscr, "DAILY CARE", ["Running local Daily Care..."])
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "/opt/lattice/bin/lattice-care-control", "run"],
            capture_output=True,
            text=True,
            timeout=1900,
        )
        if result.returncode == 0:
            message = (result.stdout or "Daily Care completed.").strip()
            title = "DAILY CARE COMPLETE"
        else:
            message = (result.stderr or result.stdout or "Daily Care failed.").strip()
            title = "DAILY CARE NEEDS ATTENTION"
    except (OSError, subprocess.TimeoutExpired) as exc:
        title = "DAILY CARE NEEDS ATTENTION"
        message = f"Daily Care could not run: {exc}"
    _control_result(stdscr, title, [message])


def _verification_control(action: str, *, timeout: int = 90) -> dict:
    if action not in {"verify-fleet", "clear-resolved"}:
        raise RuntimeError("Unsupported fleet verification action")
    result = subprocess.run(
        ["/usr/bin/sudo", "-n", "/opt/lattice/bin/lattice-verification-control", action],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    raw = (result.stdout or "").strip()
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError((result.stderr or raw or "Fleet verification returned invalid output").strip()) from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Fleet verification returned an invalid response")
    if result.returncode not in {0, 2}:
        raise RuntimeError((result.stderr or payload.get("error") or "Fleet verification failed").strip())
    return payload


def _fleet_verification_lines(report: dict) -> List[str]:
    status = str(report.get("status") or "blocked").upper()
    lines = [
        f"Fleet verification: {status}",
        f"Fleet generation: {report.get('fleet_generation') if report.get('fleet_generation') is not None else 'unknown'}",
        "",
        "ACTIVE FLEET",
    ]
    for node in list(report.get("nodes") or []):
        marker = "OK" if node.get("status") == "healthy" else "BLOCKED"
        lines.append(f"{str(node.get('hostname') or 'unknown')[:24]:24} {marker}")
        for item in list(node.get("stale_failed_units") or [])[:4]:
            lines.append(f"  resolved stale flag: {item.get('unit')}")
        for reason in list(node.get("blockers") or [])[:3]:
            lines.append(f"  {str(reason)[:110]}")
    alerts = list(report.get("alerts") or [])
    if alerts:
        lines.extend(["", "ACTIVE ALERT CHECKS"])
        for item in alerts[:12]:
            verdict = str(item.get("verdict") or "unknown").upper()
            lines.append(f"{verdict:8} {str(item.get('title') or 'Alert')[:80]}")
            if item.get("reason"):
                lines.append(f"  {str(item.get('reason'))[:110]}")
    blockers = list(report.get("blockers") or [])
    if blockers:
        lines.extend(["", "CLEAR BLOCKED"])
        for reason in blockers[:10]:
            lines.append(f"  {str(reason)[:112]}")
    elif report.get("can_clear"):
        lines.extend(["", "Every active fleet member is verified. Proven-resolved state may be cleared."])
    else:
        lines.extend(["", "Fleet is healthy. There is no proven-resolved state waiting to be cleared."])
    return lines


def _fleet_verify_clear_flow(stdscr, status_loader=None) -> None:
    _flow_message(stdscr, "VERIFY FLEET", ["Checking every active Lattice computer..."])
    try:
        report = _verification_control("verify-fleet")
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        _control_result(stdscr, "VERIFY FLEET BLOCKED", [str(exc)])
        return
    lines = _fleet_verification_lines(report)
    if report.get("status") != "pass" or not report.get("can_clear"):
        _control_result(stdscr, "VERIFY FLEET", lines)
        return
    choice = _control_menu(
        stdscr,
        "VERIFY FLEET",
        ["Clear Proven Resolved", "Back"],
        intro=lines + ["", "Clear will re-run verification before changing anything."],
    )
    if choice != 0:
        return
    _flow_message(stdscr, "CLEAR PROVEN RESOLVED", ["Re-verifying the entire active fleet..."])
    try:
        result = _verification_control("clear-resolved")
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        _control_result(stdscr, "CLEAR BLOCKED", [str(exc)])
        return
    title = "FLEET HEALTHY" if result.get("clear_status") == "cleared" else "CLEAR BLOCKED"
    summary = _fleet_verification_lines(result)
    summary.insert(1, f"Alerts resolved: {int(result.get('cleared_alerts') or 0)}")
    _control_result(stdscr, title, summary)


def _worker_care_flow(stdscr, current: LatticeStatus, status_loader=None) -> None:
    while True:
        worker = current.health.get("worker", {})
        care = dict(worker.get("care") or {})
        choice = _control_menu(
            stdscr,
            "DAILY CARE",
            ["Run Daily Care Now", "Back"],
            intro=_care_status_lines(care),
        )
        if choice is None or choice == 1:
            return
        _run_local_care(stdscr)
        if status_loader is not None:
            try:
                current = status_loader()
            except Exception:
                pass


def _master_care_flow(stdscr, current: LatticeStatus, status_loader=None) -> None:
    while True:
        rows = list(current.health.get("care_nodes", []))
        lines = [
            "Daily Care runs locally on every computer once per day.",
            "The Master displays Worker results but does not remote-run cleanup.",
            "",
            f"{'COMPUTER':<20}{'CARE':<12}{'ATTN':>6}{'CRIT':>6}",
        ]
        for row in rows:
            lines.append(
                f"{str(row.get('hostname') or 'unknown')[:18]:<20}"
                f"{str(row.get('status') or 'stale').upper():<12}"
                f"{int(row.get('attention_count') or 0):>6}"
                f"{int(row.get('critical_count') or 0):>6}"
            )
        choice = _control_menu(
            stdscr,
            "DAILY CARE",
            ["Master Care Details", "Run Daily Care Now on Master", "Verify Fleet & Clear Resolved", "Back"],
            intro=lines,
        )
        if choice is None or choice == 3:
            return
        if choice == 0:
            local = next(
                (row for row in rows if str(row.get("hostname")) == current.master_hostname),
                {"status": "stale"},
            )
            _control_result(stdscr, "MASTER DAILY CARE", _care_status_lines(local))
        elif choice == 1:
            _run_local_care(stdscr)
        elif choice == 2:
            _fleet_verify_clear_flow(stdscr, status_loader)
        if status_loader is not None:
            try:
                current = status_loader()
            except Exception:
                pass


def _worker_health_flow(stdscr, current: LatticeStatus) -> None:
    worker = current.health.get("worker", {})
    services = worker.get("services", {})
    lines = [
        f"Overall: {str(worker.get('overall') or 'unknown').upper()}",
        "",
    ]
    for name in (
        "sshd", "network", "fleet_sync", "file_transport", "file_export",
        "mounts", "shell_transport", "trusted_shell", "lattice_core", "backup",
    ):
        if name in services:
            lines.append(f"{name.replace('_', ' ').title():24} {str(services[name]).upper()}")
    _flow_message(stdscr, "LOCAL HEALTH", lines, "Press any key to return.")
    _modal_getch(stdscr)


def _worker_pairing_flow(stdscr, current: LatticeStatus) -> None:
    worker = current.health.get("worker", {})
    lines = [
        f"Worker: {worker.get('hostname') or 'unknown'}",
        f"Master: {worker.get('master_hostname') or 'unknown'}",
        f"Master IP: {worker.get('master_ip') or 'unknown'}",
        "",
        "Pairing is local to this Worker. Fleet enrollment is controlled by the Master.",
        "Credential revocation is intentionally not exposed as a one-key dashboard action.",
    ]
    _flow_message(stdscr, "PAIRING", lines, "Press any key to return.")
    _modal_getch(stdscr)


def _worker_settings_flow(stdscr, current: LatticeStatus) -> None:
    worker = current.health.get("worker", {})
    lines = [
        "This Worker intentionally does not edit fleet-wide settings.",
        "",
        f"Master: {worker.get('master_hostname') or 'unknown'}",
        "Fleet settings: MANAGED BY MASTER",
        "Backup policy: MANAGED BY MASTER",
        "File/Shell fleet policy: MANAGED BY MASTER",
        "",
        "Local network reconciliation and service state remain automatic on this Worker.",
    ]
    _flow_message(stdscr, "WORKER SETTINGS", lines, "Press any key to return.")
    _modal_getch(stdscr)


def _worker_repair_flow(stdscr, current: LatticeStatus, status_loader) -> None:
    choice = _control_menu(
        stdscr,
        "LOCAL REPAIR",
        [
            "Restart Worker Service",
            "Back",
        ],
        intro=[
            "These actions affect only this computer.",
            "Network reconciliation remains automatic and root-owned.",
            "No fleet membership or Master configuration is changed.",
        ],
    )
    if choice is None or choice == 1:
        return
    command = [
        "/usr/bin/sudo", "-n",
        "/opt/lattice/bin/lattice-action-exec",
        "restart", "lattice-worker.service",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        if result.returncode == 0:
            message = "Local repair action completed."
        else:
            message = (result.stderr or result.stdout or "Local repair failed").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"Local repair could not run: {exc}"
    _flow_message(stdscr, "LOCAL REPAIR", [message], "Press any key to return.")
    _modal_getch(stdscr)


def _worker_diagnostics_flow(stdscr, current: LatticeStatus) -> None:
    worker = current.health.get("worker", {})
    lines = [
        f"Hostname: {worker.get('hostname') or 'unknown'}",
        f"Node ID: {worker.get('node_id') or 'unknown'}",
        f"Master: {worker.get('master_hostname') or 'unknown'} ({worker.get('master_ip') or 'unknown'})",
        f"Worker daemon: {current.daemon_status}",
        f"Uptime: {current.uptime}",
        "",
        f"Fleet generation: {worker.get('fleet_generation', 0)}",
        f"File generation: {worker.get('file_generation', 0)}",
        f"Shell generation: {worker.get('shell_generation', 0)}",
        f"In sync: {'YES' if worker.get('in_sync') else 'NO'}",
        "",
        f"Mounted peers: {len(worker.get('mounts', []))}",
        f"Shell peers: {len(worker.get('shell_connections', []))}",
        f"Backup jobs: {len(worker.get('backup_jobs', []))}",
        f"Hosted Backup targets: {len(worker.get('hosted_targets', []))}",
    ]
    _flow_message(stdscr, "WORKER DIAGNOSTICS", lines, "Press any key to return.")
    _modal_getch(stdscr)


def show_worker_menu(stdscr, status: LatticeStatus, status_loader=None):
    """Role-correct Worker dashboard. Master-only controls are never rendered."""
    curses.curs_set(0)
    curses.start_color()
    bg = curses.COLOR_BLACK
    curses.init_pair(1, curses.COLOR_CYAN, bg)
    curses.init_pair(2, curses.COLOR_MAGENTA, bg)
    curses.init_pair(3, curses.COLOR_WHITE, bg)
    curses.init_pair(4, curses.COLOR_GREEN, bg)
    curses.init_pair(5, curses.COLOR_YELLOW, bg)
    curses.init_pair(6, curses.COLOR_RED, bg)
    if hasattr(stdscr, "timeout"):
        stdscr.timeout(1000)

    menu_items = ["Backup", "Health", "Pairing", "Settings", "Repair", "Diagnostics", "Exit", "Care"]
    selected = 0
    current = status
    last_refresh = time.monotonic()

    while True:
        if status_loader is not None and time.monotonic() - last_refresh >= 5:
            try:
                current = status_loader()
            except Exception:
                pass
            last_refresh = time.monotonic()

        worker = current.health.get("worker", {})
        height, width = stdscr.getmaxyx()
        compact = width < 90 or height < 30
        panel_width = min(96, max(40, width - 4))
        x = max(0, (width - panel_width) // 2)
        stdscr.erase()

        overall = str(worker.get("overall") or "unknown").upper()
        overall_ok = overall == "HEALTHY"
        master_name = str(worker.get("master_hostname") or "unknown")
        master_ip = str(worker.get("master_ip") or "unknown")
        master_configured = bool(
            master_name and master_name != "unknown"
            and master_ip and master_ip != "unknown"
        )
        backup_jobs = list(worker.get("backup_jobs", []))
        backup_label = "NOT SET UP"
        backup_ok = False
        care = dict(worker.get("care") or {})
        care_label = str(care.get("status") or "stale").upper()
        care_ok = care_label == "HEALTHY"
        if backup_jobs:
            labels = [_worker_backup_label(job) for job in backup_jobs]
            backup_ok = all(item[1] for item in labels)
            backup_label = "HEALTHY" if all(item[0] == "HEALTHY" for item in labels) else labels[0][0]

        lines = []
        def add(text="", color=3):
            lines.append((str(text), color))

        if compact:
            add(f"LATTICE — WORKER  {worker.get('hostname') or 'unknown'}", 2)
            add(f"STATUS {'●' if overall_ok else '○'} {overall}", 4 if overall_ok else 5)
            add("")
            add(
                f"MASTER  {'●' if master_configured else '○'} {master_name}  {master_ip}",
                4 if master_configured else 5,
            )
            add("")
            add("LOCAL HEALTH", 1)
            services = worker.get("services", {})
            for label, key in (
                ("Worker", "lattice_core"),
                ("Files", "mounts"),
                ("Shell", "trusted_shell"),
            ):
                state = str(services.get(key) or "unknown").upper()
                ok = state == "HEALTHY"
                add(f"{'●' if ok else '○'} {label:<10} {state}", 4 if ok else 5)
            add(f"{'●' if backup_ok else '○'} {'Backup':<10} {backup_label}", 4 if backup_ok else 5)
            add(f"{'●' if care_ok else '○'} {'Care':<10} {care_label}", 4 if care_ok else 5)
            add("")
            add("PEERS", 1)
            mounts = {m.get("hostname"): m for m in worker.get("mounts", [])}
            shells = {s.get("hostname"): s for s in worker.get("shell_connections", [])}
            names = sorted(set(mounts) | set(shells))
            if names:
                for name in names[:5]:
                    f_ok = mounts.get(name, {}).get("state") == "mounted"
                    s_ok = shells.get(name, {}).get("state") == "connected"
                    add(f"{str(name)[:16]:<17} F{'●' if f_ok else '○'}  S{'●' if s_ok else '○'}", 4 if f_ok and s_ok else 5)
            else:
                add("No peer state available", 5)
            add("")
            add(
                f"SYNC  Fleet {worker.get('fleet_generation',0)}  "
                f"File {worker.get('file_generation',0)}  Shell {worker.get('shell_generation',0)}",
                4 if worker.get("in_sync") else 5,
            )
            if worker.get("hosted_targets"):
                target = worker["hosted_targets"][0]
                add("")
                add("BACKUP STORAGE", 1)
                add(
                    f"{str(target.get('friendly_name') or 'Backup Storage')[:24]}  "
                    f"{str(target.get('health') or 'unknown').upper()}  "
                    f"Free {_human_bytes(target.get('free_bytes'))}",
                    4 if target.get("health") == "healthy" else 5,
                )
        else:
            add(f"{'LATTICE WORKER — ' + str(worker.get('hostname') or 'unknown'):^{panel_width}}", 2)
            add(
                f"{'STATUS ' + ('● ' if overall_ok else '○ ') + overall:<{panel_width//2}}"
                f"MASTER {'●' if master_configured else '○'} {master_name}",
                4 if overall_ok and master_configured else 5,
            )
            add("")
            add("MASTER CONNECTION", 1)
            add(
                f"  {'●' if master_configured else '○'} {master_name:<22} {master_ip:<16} "
                f"{'CONFIGURED' if master_configured else 'UNKNOWN'}",
                4 if master_configured else 5,
            )
            add("")
            add("LOCAL HEALTH", 1)
            services = worker.get("services", {})
            for label, key in (
                ("Worker Service", "lattice_core"),
                ("Fleet Sync", "fleet_sync"),
                ("File Access", "mounts"),
                ("Trusted Shell", "trusted_shell"),
            ):
                state = str(services.get(key) or "unknown").upper()
                ok = state == "HEALTHY"
                add(f"  {'●' if ok else '○'} {label:<22} {state}", 4 if ok else 5)
            add(f"  {'●' if backup_ok else '○'} {'Backup':<22} {backup_label}", 4 if backup_ok else 5)
            add(f"  {'●' if care_ok else '○'} {'Daily Care':<22} {care_label}", 4 if care_ok else 5)
            add("")
            add("PEER CONNECTIONS", 1)
            add(f"  {'HOSTNAME':<22}{'FILE / MOUNT':<18}SHELL")
            mounts = {m.get("hostname"): m for m in worker.get("mounts", [])}
            shells = {s.get("hostname"): s for s in worker.get("shell_connections", [])}
            names = sorted(set(mounts) | set(shells))
            for name in names[:8]:
                f_state = str(mounts.get(name, {}).get("state") or "unknown").upper()
                s_state = str(shells.get(name, {}).get("state") or "unknown").upper()
                ok = f_state == "MOUNTED" and s_state == "CONNECTED"
                add(f"  {str(name)[:20]:<22}{f_state:<18}{s_state}", 4 if ok else 5)
            if not names:
                add("  No peer state available", 5)
            add("")
            add("SYNCHRONIZATION", 1)
            add(
                f"  Fleet {worker.get('fleet_generation',0)}   "
                f"File {worker.get('file_generation',0)}   "
                f"Shell {worker.get('shell_generation',0)}   "
                f"{'● IN SYNC' if worker.get('in_sync') else '○ OUT OF SYNC'}",
                4 if worker.get("in_sync") else 5,
            )
            add("")
            add("BACKUP", 1)
            if backup_jobs:
                for job in backup_jobs[:2]:
                    label, ok = _worker_backup_label(job)
                    obs = job.get("observation") or {}
                    add(f"  Destination  {job.get('friendly_name') or 'unknown'}")
                    add(f"  Status       {'●' if ok else '○'} {label}", 4 if ok else 5)
                    add(f"  Last Backup  {obs.get('last_success_at') or 'none yet'}")
                    add(f"  Failures     {obs.get('failure_streak',0)}")
            else:
                add("  ○ NOT SET UP", 5)
            if worker.get("hosted_targets"):
                add("")
                add("BACKUP STORAGE HOSTED HERE", 1)
                for target in worker["hosted_targets"][:2]:
                    healthy = target.get("health") == "healthy" and bool(target.get("present"))
                    add(
                        f"  {'●' if healthy else '○'} "
                        f"{str(target.get('friendly_name') or 'Backup Storage')[:28]:<29}"
                        f"{str(target.get('health') or 'unknown').upper():<10}"
                        f" Capacity {_human_bytes(target.get('total_bytes')):<12}"
                        f" Free {_human_bytes(target.get('free_bytes'))}",
                        4 if healthy else 5,
                    )

        footer_names = (
            ["Bkp", "Health", "Pair", "Set", "Fix", "Diag", "Exit", "Care"]
            if compact else menu_items
        )
        footer = "  ".join(
            f"{'>' if i == selected else ' '}[{i+1}]{name}"
            for i, name in enumerate(footer_names)
        )
        max_body = max(1, height - 4)
        for y, (text, color) in enumerate(lines[:max_body]):
            _safe_addstr(stdscr, y + 1, x, text[:panel_width], curses.color_pair(color))
        _safe_addstr(stdscr, height - 2, x, footer[:panel_width], curses.color_pair(3))
        stdscr.refresh()

        key = stdscr.getch()
        if key == -1:
            continue
        if key == curses.KEY_RESIZE:
            continue
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(menu_items)
            continue
        if key == curses.KEY_DOWN:
            selected = (selected + 1) % len(menu_items)
            continue
        if ord('1') <= key <= ord('8'):
            selected = key - ord('1')
            direct = True
        else:
            direct = False
        if key in (ord('q'), ord('Q')):
            return 6
        if key in (ord('\n'), ord('\r'), curses.KEY_ENTER) or direct:
            if selected == 6:
                return selected
            if selected == 0:
                _worker_backup_flow(stdscr, current, status_loader)
            elif selected == 1:
                _worker_health_flow(stdscr, current)
            elif selected == 2:
                _worker_pairing_flow(stdscr, current)
            elif selected == 3:
                _worker_settings_flow(stdscr, current)
            elif selected == 4:
                _worker_repair_flow(stdscr, current, status_loader)
            elif selected == 5:
                _worker_diagnostics_flow(stdscr, current)
            elif selected == 7:
                _worker_care_flow(stdscr, current, status_loader)
            if status_loader is not None:
                try:
                    current = status_loader()
                except Exception:
                    pass
            last_refresh = time.monotonic()


def show_re_run_menu(stdscr, status: LatticeStatus,
                     discovery_monitor: Optional[DiscoveryMonitor] = None,
                     status_loader=None):
    if status.role == "worker":
        return show_worker_menu(stdscr, status, status_loader)
    curses.curs_set(0)
    curses.start_color()
    bg = curses.COLOR_BLACK
    curses.init_pair(1, curses.COLOR_CYAN, bg)
    curses.init_pair(2, curses.COLOR_MAGENTA, bg)
    curses.init_pair(3, curses.COLOR_WHITE, bg)
    curses.init_pair(4, curses.COLOR_GREEN, bg)
    curses.init_pair(5, curses.COLOR_YELLOW, bg)
    curses.init_pair(6, curses.COLOR_RED, bg)
    stdscr.bkgd(' ', curses.color_pair(0))
    if hasattr(stdscr, "timeout"):
        stdscr.timeout(1000)

    menu_items = [
        "Add Computer",
        "Remove Computer",
        "Backups",
        "Settings",
        "Health Check",
        "FIX",
        "Reset Lattice",
        "Exit",
        "Daily Care",
    ]
    selected = 0
    worker_offset = 0
    view_offset = 0
    current = status
    last_status_refresh = time.monotonic()
    status_error = None

    def append(lines, text, color=3):
        lines.append((text, curses.color_pair(color)))

    def centered(text: str, width: int) -> str:
        return text.center(width)

    while True:
        now = time.monotonic()
        if status_loader is not None and now - last_status_refresh >= STATUS_REFRESH_SECONDS:
            try:
                current = status_loader()
                status_error = None
            except Exception as exc:
                status_error = str(exc)
            last_status_refresh = now

        max_y, max_x = stdscr.getmaxyx()
        render_height = min(max_y, MAX_DASHBOARD_HEIGHT)
        render_width = min(max_x, 67)
        mode = _dashboard_mode(render_height, max_x)
        stdscr.clear()

        if mode == "tiny":
            messages = [
                "Lattice dashboard is waiting for more terminal space.",
                f"Current: {max_x}x{max_y}   Minimum: {MIN_DASHBOARD_WIDTH}x{MIN_DASHBOARD_HEIGHT}",
                "Resize the terminal and Lattice will redraw automatically.",
                "Press Q to exit.",
            ]
            top = max(0, (max_y - len(messages)) // 2)
            for index, message in enumerate(messages):
                x = max(0, (max_x - len(message)) // 2)
                _safe_addstr(stdscr, top + index, x, message, curses.A_BOLD if index == 0 else 0)
            stdscr.refresh()
            key = stdscr.getch()
            if key in (ord('q'), ord('Q')):
                return len(menu_items) - 1
            continue

        discovery = (
            discovery_monitor.snapshot(now)
            if discovery_monitor is not None
            else _passive_discovery_snapshot()
        )
        panel_width = min(67, max_x - 2)
        x_offset = max(0, (max_x - panel_width) // 2)
        y_offset = max(0, (max_y - render_height) // 2)
        section_sep = "─" * min(64, panel_width)
        lines: List[tuple[str, int]] = []
        heartbeat_overlays: List[tuple[str, List[tuple[int, str, int]]]] = []
        mesh_overlays: List[tuple[str, List[tuple[int, str, int]]]] = []
        detail_overlays: List[tuple[str, List[tuple[int, str, int]]]] = []
        problem_overlays: List[tuple[str, List[tuple[int, str, int]]]] = []

        fleet = current.health.get("fleet", {})
        nodes = int(fleet.get("nodes", 1 + len(current.workers)))
        online_workers = int(
            fleet.get(
                "online",
                sum(1 for w in current.workers if w.get("status") not in {"down", "disabled"}),
            )
        )
        online_nodes = 1 + online_workers
        fleet_state = str(fleet.get("state") or "unknown")
        fleet_word = "● HEALTHY" if fleet_state == "healthy" else (
            "⚠ DEGRADED" if fleet_state == "degraded" else "○ UNKNOWN"
        )

        workers = [dict(worker) for worker in current.workers]
        mesh_limit = 4 if mode == "full" else 2
        max_worker_offset = max(0, len(workers) - mesh_limit)
        worker_offset = min(worker_offset, max_worker_offset)
        network = current.health.get("network", {"state": "unknown", "label": "Unknown"})
        network_state = str(network.get("state") or "unknown")
        network_word = "STABLE" if network_state == "healthy" else (
            "DEGRADED" if network_state == "degraded" else "UNKNOWN"
        )
        daemon_word = current.daemon_status.upper()
        automation = current.health.get("automation", {})

        node_access_rows = list(current.health.get("node_access", []))
        access_by_hostname = {
            str(row.get("hostname") or "unknown"): row
            for row in node_access_rows
        }
        backup_rows = list(current.health.get("backup_nodes", []))
        backup_by_hostname = {
            str(row.get("hostname") or "unknown"): row
            for row in backup_rows
        }
        care_rows = list(current.health.get("care_nodes", []))
        care_by_hostname = {
            str(row.get("hostname") or "unknown"): row
            for row in care_rows
        }
        active_alert_workers = {
            str(alert.get("worker") or "Master")
            for alert in current.alerts
        }
        mesh_now = datetime.now(timezone.utc)
        for worker in workers:
            hostname = str(worker.get("hostname") or "unknown")
            worker["mesh_status"] = _mesh_worker_status(
                worker,
                access_by_hostname.get(hostname),
                has_active_alert=hostname in active_alert_workers,
                now=mesh_now,
            )
        visible_workers = workers[worker_offset:worker_offset + mesh_limit]
        master_has_alert = bool(
            {"Master", current.master_hostname} & active_alert_workers
        )
        master_mesh_status = _mesh_master_status(
            current.daemon_status,
            network_state,
            access_by_hostname.get(current.master_hostname),
            has_active_alert=master_has_alert,
        )
        master_health_word = (
            "● HEALTHY" if master_mesh_status == "HEALTHY" else
            "⚠ DEGRADED" if master_mesh_status == "DEGRADED" else
            f"○ {master_mesh_status}"
        )
        # The dashboard redraws every second, so pulse healthy dots ourselves
        # instead of relying on terminal-specific support for curses.A_BLINK.
        pulse_on = int(now) % 2 == 0

        if discovery.get("error"):
            scanner = "⚠ ERROR"
            scanner_color = 6
        elif discovery_monitor is None:
            scanner = "○ INACTIVE"
            scanner_color = 3
        elif discovery.get("scanning"):
            scanner = "◌ SCANNING..."
            scanner_color = 5
        else:
            scanner = "● ACTIVE"
            scanner_color = 4
        scan_age = _relative_seconds(discovery.get("last_scan_age"))
        waiting = list(discovery.get("waiting", []))
        discovery_network = str(current.health.get("discovery_network") or "unknown")

        if mode == "full":
            banner_width = min(64, panel_width)
            banner_indent = " " * max(0, (panel_width - banner_width) // 2)

            def section_heading(title: str) -> str:
                width = min(64, panel_width)
                middle = f" {title} "
                remaining = max(0, width - len(middle))
                left = remaining // 2
                return ("─" * left) + middle + ("─" * (remaining - left))

            def centered_rule(label: str) -> str:
                width = min(64, panel_width)
                middle = f" {label} "
                remaining = max(0, width - len(middle))
                left = remaining // 2
                return ("─" * left) + middle + ("─" * (remaining - left))

            # Main Lattice header: spacious identity with one high-value status row.
            title = " LATTICE "
            remaining = max(0, banner_width - 2 - len(title))
            left = remaining // 2
            right = remaining - left
            top = "╔" + ("═" * left) + title + ("═" * right) + "╗"
            empty = "║" + (" " * (banner_width - 2)) + "║"
            node_icon = "●" if online_nodes == nodes else "⚠"
            alert_status = "✓ 0" if not current.alerts else f"⚠ {len(current.alerts)}"
            status_payload = (
                f"  FLEET   {fleet_word}       NODES   {node_icon} {online_nodes}/{nodes}"
                f"       ALERTS   {alert_status}  "
            )
            body = "║" + status_payload[:banner_width - 2].ljust(banner_width - 2) + "║"
            bottom = "╚" + ("═" * (banner_width - 2)) + "╝"
            append(lines, banner_indent + top, 2)
            append(lines, banner_indent + empty, 2)
            append(lines, banner_indent + body, 4 if fleet_state == "healthy" else 5)
            append(lines, banner_indent + empty, 2)
            append(lines, banner_indent + bottom, 2)
            append(lines, "")

            # Discovery is a single boxed banner directly below the main header.
            discovery_label = " DISCOVERY "
            discovery_inner = banner_width - 2
            discovery_remaining = max(0, discovery_inner - len(discovery_label))
            discovery_left = discovery_remaining // 2
            discovery_top = (
                "┌" + ("─" * discovery_left) + discovery_label
                + ("─" * (discovery_remaining - discovery_left)) + "┐"
            )
            discovery_payload = (
                f" {scanner}   Network {discovery_network}   Scan {scan_age}   Waiting {len(waiting)} "
            )
            discovery_body = "│" + discovery_payload[:banner_width - 2].ljust(banner_width - 2) + "│"
            discovery_bottom = "└" + ("─" * (banner_width - 2)) + "┘"
            append(lines, banner_indent + discovery_top, 1)
            append(lines, banner_indent + discovery_body, scanner_color)
            append(lines, banner_indent + discovery_bottom, 1)
            if status_error:
                append(lines, banner_indent + f"⚠ Dashboard refresh error: {status_error}", 6)

            # Keep alerts compact: one active alert per row with no decorative
            # whitespace between Discovery, Alerts, and Current Mesh.
            if not current.alerts:
                append(lines, centered_rule("✓ NO ALERTS"), 4)
            else:
                append(lines, section_heading("ALERTS"), 3)
                alert_limit = 2
                for alert in current.alerts[:alert_limit]:
                    worker = str(alert.get("worker") or "Master")[:18]
                    title_text = str(alert.get("title") or "Active alert").replace("\n", " ")
                    alert_text = f"⚠ {worker:<18} {title_text}"
                    append(lines, alert_text[:min(64, panel_width)], 5)
                if len(current.alerts) > alert_limit:
                    append(lines, f"+ {len(current.alerts) - alert_limit} more active alert(s)", 5)

            # Current mesh remains the visual center of the dashboard.
            append(lines, section_heading("CURRENT MESH"), 3)
            append(lines, "")
            master_symbol = _mesh_node_symbol(master_mesh_status, pulse_on)
            append(
                lines,
                centered(f"{master_symbol} {current.master_hostname}", panel_width),
                _mesh_status_color(master_mesh_status),
            )
            append(lines, centered("MASTER", panel_width), 3)
            append(lines, centered(str(current.master_ip), panel_width), 3)
            append(lines, centered("HB LOCAL", panel_width), 4)
            heartbeat_color = {"fresh": 4, "warning": 5, "stale": 6, "unknown": 5}
            if len(visible_workers) >= 2:
                append(lines, centered("/     \\", panel_width), 3)
                append(lines, centered("/       \\", panel_width), 3)
                left_worker, right_worker = visible_workers[0], visible_workers[1]
                left_status = str(left_worker.get("mesh_status") or "UNKNOWN")
                right_status = str(right_worker.get("mesh_status") or "UNKNOWN")
                left_symbol = _mesh_node_symbol(left_status, pulse_on)
                right_symbol = _mesh_node_symbol(right_status, pulse_on)

                node_row = centered(
                    f"{left_symbol:^22}    {right_symbol:^22}", panel_width
                )
                left_node_pos = node_row.find(left_symbol)
                right_node_pos = node_row.find(
                    right_symbol, left_node_pos + len(left_symbol)
                )
                append(lines, node_row, 3)
                mesh_overlays.append((node_row, [
                    (left_node_pos, left_symbol, _mesh_status_color(left_status)),
                    (right_node_pos, right_symbol, _mesh_status_color(right_status)),
                ]))

                append(lines, centered(
                    f"{str(left_worker.get('hostname') or 'unknown')[:20]:^22}    "
                    f"{str(right_worker.get('hostname') or 'unknown')[:20]:^22}", panel_width), 3)
                status_row = centered(
                    f"{left_status:^22}    {right_status:^22}", panel_width
                )
                left_status_pos = status_row.find(left_status)
                right_status_pos = status_row.find(
                    right_status, left_status_pos + len(left_status)
                )
                append(lines, status_row, 3)
                mesh_overlays.append((status_row, [
                    (left_status_pos, left_status, _mesh_status_color(left_status)),
                    (right_status_pos, right_status, _mesh_status_color(right_status)),
                ]))

                append(lines, centered(
                    f"{str(left_worker.get('ip') or 'no address'):^22}    "
                    f"{str(right_worker.get('ip') or 'no address'):^22}", panel_width), 3)
                left_hb, left_hb_state = _heartbeat_display(left_worker.get("last_seen"))
                right_hb, right_hb_state = _heartbeat_display(right_worker.get("last_seen"))
                heartbeat_row = f"{left_hb:^22}    {right_hb:^22}"
                heartbeat_line = centered(heartbeat_row, panel_width)
                left_pos = heartbeat_line.find(left_hb)
                right_pos = heartbeat_line.find(right_hb, left_pos + len(left_hb))
                append(lines, heartbeat_line, 3)
                heartbeat_overlays.append((heartbeat_line, [
                    (left_pos, left_hb, heartbeat_color[left_hb_state]),
                    (right_pos, right_hb, heartbeat_color[right_hb_state]),
                ]))
                for worker in visible_workers[2:]:
                    status = str(worker.get("mesh_status") or "UNKNOWN")
                    append(
                        lines,
                        f"  └─ {_worker_display(worker, pulse_on=pulse_on)}",
                        _mesh_status_color(status),
                    )
                    worker_hb, worker_hb_state = _heartbeat_display(worker.get("last_seen"))
                    worker_hb_line = f"     {worker_hb}"
                    append(lines, worker_hb_line, 3)
                    heartbeat_overlays.append((worker_hb_line, [
                        (worker_hb_line.find(worker_hb), worker_hb, heartbeat_color[worker_hb_state]),
                    ]))
            elif len(visible_workers) == 1:
                worker = visible_workers[0]
                status = str(worker.get("mesh_status") or "UNKNOWN")
                symbol = _mesh_node_symbol(status, pulse_on)
                append(lines, centered("│", panel_width), 3)
                append(lines, centered(symbol, panel_width), _mesh_status_color(status))
                append(lines, centered(str(worker.get("hostname") or "unknown"), panel_width), 3)
                append(lines, centered(status, panel_width), _mesh_status_color(status))
                append(lines, centered(str(worker.get("ip") or "no address"), panel_width), 3)
                worker_hb, worker_hb_state = _heartbeat_display(worker.get("last_seen"))
                worker_hb_line = centered(worker_hb, panel_width)
                append(lines, worker_hb_line, 3)
                heartbeat_overlays.append((worker_hb_line, [
                    (worker_hb_line.find(worker_hb), worker_hb, heartbeat_color[worker_hb_state]),
                ]))
            else:
                append(lines, centered("No Workers paired yet", panel_width), 3)
            if len(workers) > mesh_limit:
                first = worker_offset + 1
                last = worker_offset + len(visible_workers)
                append(lines, f"Workers {first}-{last} of {len(workers)} — PgUp/PgDn mesh", 3)
            append(lines, "")
            append(lines, "")

            # Full view uses the otherwise-empty right half for automation state.
            # Compact mode remains intentionally unchanged below.
            append(lines, section_heading("MASTER DETAILS"), 3)
            append(lines, "")
            details_width = min(64, panel_width)
            details_split = 41

            def detail_pair(left: str, right: str) -> str:
                return (f"{left:<{details_split}}{right}")[:details_width]

            master_identity = (
                f"● {current.master_hostname}   MASTER   {current.master_ip}"
            )
            identity_row = detail_pair(master_identity, "AUTOMATION")
            append(lines, identity_row, 3)
            detail_overlays.append((identity_row, [(
                identity_row.find(master_identity),
                master_identity,
                4 if current.daemon_status == "running" else 6,
            )]))

            network_detail = f"{_state_icon(network_state)} {network_word}"
            daemon_state = "healthy" if current.daemon_status == "running" else "degraded"
            daemon_detail = f"{_state_icon(daemon_state)} {daemon_word}"

            auto_mode = str(automation.get("mode") or "alert_only")
            autoheal_detail = "● AUTOMATIC" if auto_mode == "automatic" else "○ ALERT ONLY"
            autoheal_color = 4 if auto_mode == "automatic" else 5
            dry_run = bool(automation.get("dry_run", True))
            dry_run_detail = "⚠ ON" if dry_run else "○ OFF"
            dry_run_color = 5 if dry_run else 4
            breaker_state = str(automation.get("breaker_state") or "unknown")
            breaker_label = str(automation.get("breaker_label") or "UNKNOWN")
            if breaker_state == "healthy":
                breaker_detail, breaker_color = f"✓ {breaker_label}", 4
            elif breaker_state == "degraded":
                breaker_detail, breaker_color = f"⚠ {breaker_label}", 6
            else:
                breaker_detail, breaker_color = f"⚠ {breaker_label}", 5
            last_fix = automation.get("last_fix")
            last_fix_detail = (
                f"✓ {_relative_timestamp(last_fix)}" if last_fix else "○ none yet"
            )
            last_fix_color = 4 if last_fix else 3

            detail_rows = [
                (
                    f"Health      {master_health_word}",
                    f"Auto-Heal  {autoheal_detail}",
                    master_health_word, _mesh_status_color(master_mesh_status),
                    autoheal_detail, autoheal_color,
                ),
                (
                    f"Network     {network_detail}",
                    f"Dry Run    {dry_run_detail}",
                    network_detail, 4 if network_state == "healthy" else 5,
                    dry_run_detail, dry_run_color,
                ),
                (
                    f"Daemon      {daemon_detail}",
                    f"Breakers   {breaker_detail}",
                    daemon_detail, 4 if daemon_state == "healthy" else 6,
                    breaker_detail, breaker_color,
                ),
                (
                    f"Uptime      {current.uptime}",
                    f"Last Fix   {last_fix_detail}",
                    "", 3,
                    last_fix_detail, last_fix_color,
                ),
            ]
            for left, right, left_span, left_color, right_span, right_color in detail_rows:
                row = detail_pair(left, right)
                append(lines, row, 3)
                spans = []
                if left_span:
                    left_pos = row.find(left_span)
                    if left_pos >= 0:
                        spans.append((left_pos, left_span, left_color))
                right_pos = row.find(right_span, min(details_split, len(row)))
                if right_pos >= 0:
                    spans.append((right_pos, right_span, right_color))
                if spans:
                    detail_overlays.append((row, spans))

            append(lines, "")

            # Full view keeps one dense row per node so the same information
            # uses much less vertical space. Compact mode keeps its current layout.
            append(lines, section_heading("NODE CONNECTIONS"), 3)
            append(lines, "")
            access_rows = list(node_access_rows)
            if not access_rows:
                access_rows = [{
                    "hostname": current.master_hostname, "file": "UNKNOWN", "file_ok": False,
                    "shell": "UNKNOWN", "shell_ok": False, "admin": "UNKNOWN", "admin_ok": False,
                }]
                access_rows.extend({
                    "hostname": str(w.get("hostname") or "unknown"), "file": "UNKNOWN", "file_ok": False,
                    "shell": "UNKNOWN", "shell_ok": False, "admin": "UNKNOWN", "admin_ok": False,
                } for w in workers)

            host_width = 15
            file_width = 13
            shell_width = 10
            admin_width = 7
            backup_width = 9
            care_width = 10

            def connection_status(icon: str, label: str, width: int) -> str:
                spaced = f"{icon} {label}"
                if len(spaced) <= width:
                    return spaced
                compact = f"{icon}{label}"
                return compact if len(compact) <= width else compact[:width]

            def connection_cell(text: str, width: int) -> tuple[str, str]:
                """Return a hard-bounded cell and the exact visible overlay text."""
                visible = str(text)[:width]
                return f"{visible:<{width}}", visible
            connection_header = (
                f"{'':<{host_width}}{'FILE / MOUNT':<{file_width}}"
                f"{'SHELL':<{shell_width}}{'ADMIN':<{admin_width}}"
                f"{'BACKUP':<{backup_width}}CARE"
            )[:details_width]
            append(lines, connection_header, 3)
            for access in access_rows:
                file_icon = "●" if access.get("file_ok") else "✗"
                shell_icon = "●" if access.get("shell_ok") else "✗"
                admin_icon = "●" if access.get("admin_ok") else "✗"
                file_text = connection_status(file_icon, str(access.get('file') or 'UNKNOWN'), file_width)
                shell_text = connection_status(shell_icon, str(access.get('shell') or 'UNKNOWN'), shell_width)
                admin_text = connection_status(admin_icon, str(access.get('admin') or 'UNKNOWN'), admin_width)
                hostname = str(access.get("hostname") or "unknown")
                backup = backup_by_hostname.get(
                    hostname,
                    {"label": "NOT SET UP", "ok": False, "state": "not_set_up"},
                )
                backup_icon = "●" if backup.get("ok") else "○"
                backup_text = connection_status(backup_icon, str(backup.get('label') or 'UNKNOWN'), backup_width)
                care = care_by_hostname.get(hostname, {"status": "stale"})
                care_state = str(care.get("status") or "stale")
                care_ok = care_state == "healthy"
                care_text = connection_status('●' if care_ok else '○', care_state.upper(), care_width)
                row_ok = bool(
                    access.get("file_ok") and access.get("shell_ok") and access.get("admin_ok")
                    and backup.get("ok") and care_ok
                )
                host_text = f"● {hostname}"
                host_cell, host_visible = connection_cell(host_text, host_width)
                file_cell, file_visible = connection_cell(file_text, file_width)
                shell_cell, shell_visible = connection_cell(shell_text, shell_width)
                admin_cell, admin_visible = connection_cell(admin_text, admin_width)
                backup_cell, backup_visible = connection_cell(backup_text, backup_width)
                care_cell, care_visible = connection_cell(care_text, care_width)
                row = (
                    host_cell
                    + file_cell
                    + shell_cell
                    + admin_cell
                    + backup_cell
                    + care_cell
                )[:details_width]
                append(lines, row, 3)
                spans = [(0, host_visible, 4 if row_ok else 5)]
                file_pos = host_width
                shell_pos = host_width + file_width
                admin_pos = host_width + file_width + shell_width
                backup_pos = admin_pos + admin_width
                care_pos = backup_pos + backup_width
                backup_state = str(backup.get("state") or "unknown")
                backup_color = 4 if backup_state in {"healthy", "running", "ready"} else (
                    5 if backup_state in {"paused", "off", "not_set_up", "unknown"} else 6
                )
                spans.extend([
                    (file_pos, file_visible, 4 if access.get("file_ok") else 6),
                    (shell_pos, shell_visible, 4 if access.get("shell_ok") else 6),
                    (admin_pos, admin_visible, 4 if access.get("admin_ok") else 6),
                    (backup_pos, backup_visible, backup_color),
                    (care_pos, care_visible, 4 if care_ok else (6 if care_state == "critical" else 5)),
                ])
                detail_overlays.append((row, spans))

            # The last five persisted Lattice events form a compact live log strip.
            append(lines, "")
            append(lines, section_heading("RECENT LOGS"), 3)
            if current.events:
                for event in current.events[:5]:
                    row, color = _recent_log_row(event, min(64, panel_width))
                    append(lines, row, color)
            else:
                append(lines, "○ No recent Lattice events", 3)

            if current.problems:
                append(lines, section_heading("RECENT PROBLEMS"), 3)
                for problem in current.problems[:5]:
                    row, color, overlay = _recent_problem_row(problem, min(64, panel_width))
                    append(lines, row, color)
                    if overlay is not None:
                        problem_overlays.append((row, [overlay]))
        else:
            # Compact mode is the same dashboard compressed into rows instead
            # of the full graphical mesh.  It uses the same operational health,
            # heartbeat, alert, and connection evidence as full mode.
            compact_width = min(64, panel_width)
            compact_indent = " " * max(0, (panel_width - compact_width) // 2)

            def compact_heading(title: str) -> str:
                middle = f" {title} "
                remaining = max(0, compact_width - len(middle))
                left = remaining // 2
                return ("─" * left) + middle + ("─" * (remaining - left))

            # Header mirrors the full dashboard but drops decorative blank rows.
            title = " LATTICE "
            remaining = max(0, compact_width - 2 - len(title))
            left = remaining // 2
            right = remaining - left
            top = "╔" + ("═" * left) + title + ("═" * right) + "╗"
            node_icon = "●" if online_nodes == nodes else "⚠"
            alert_status = "✓ 0" if not current.alerts else f"⚠ {len(current.alerts)}"
            payload = (
                f" FLEET {fleet_word}    NODES {node_icon} {online_nodes}/{nodes}"
                f"    ALERTS {alert_status} "
            )
            body = "║" + payload[:compact_width - 2].ljust(compact_width - 2) + "║"
            bottom = "╚" + ("═" * (compact_width - 2)) + "╝"
            append(lines, compact_indent + top, 2)
            append(lines, compact_indent + body, 4 if fleet_state == "healthy" else 5)
            append(lines, compact_indent + bottom, 2)

            # Discovery stays directly below status, matching full mode.
            discovery_label = " DISCOVERY "
            discovery_inner = compact_width - 2
            discovery_remaining = max(0, discovery_inner - len(discovery_label))
            discovery_left = discovery_remaining // 2
            discovery_top = (
                "┌" + ("─" * discovery_left) + discovery_label
                + ("─" * (discovery_remaining - discovery_left)) + "┐"
            )
            discovery_payload = (
                f" {scanner}   {discovery_network}   Scan {scan_age}   Waiting {len(waiting)} "
            )
            discovery_body = (
                "│" + discovery_payload[:compact_width - 2].ljust(compact_width - 2) + "│"
            )
            discovery_bottom = "└" + ("─" * (compact_width - 2)) + "┘"
            append(lines, compact_indent + discovery_top, 1)
            append(lines, compact_indent + discovery_body, scanner_color)
            append(lines, compact_indent + discovery_bottom, 1)
            if status_error:
                append(lines, f"⚠ Dashboard refresh error: {status_error}"[:compact_width], 6)

            # Alerts stay one row each, directly above the compact mesh.
            if not current.alerts:
                append(lines, compact_heading("✓ NO ALERTS"), 4)
            else:
                append(lines, compact_heading("ALERTS"), 3)
                compact_alert_limit = 2
                for alert in current.alerts[:compact_alert_limit]:
                    worker = str(alert.get("worker") or "Master")[:16]
                    title_text = str(alert.get("title") or "Active alert").replace("\n", " ")
                    append(lines, f"⚠ {worker:<16} {title_text}"[:compact_width], 5)
                if len(current.alerts) > compact_alert_limit:
                    append(lines, f"+ {len(current.alerts) - compact_alert_limit} more active alert(s)"[:compact_width], 5)

            # A row-based tree is clearer than squeezing the large triangular mesh.
            append(lines, compact_heading("CURRENT MESH"), 3)
            master_symbol = _mesh_node_symbol(master_mesh_status, pulse_on)
            master_row = (
                f"{master_symbol} {current.master_hostname[:16]:<16}  "
                f"MASTER      {str(current.master_ip):<15} HB LOCAL"
            )[:compact_width]
            append(lines, master_row, 3)
            master_symbol_pos = master_row.find(master_symbol)
            if master_symbol_pos >= 0:
                mesh_overlays.append((master_row, [
                    (master_symbol_pos, master_symbol, _mesh_status_color(master_mesh_status)),
                ]))
            local_pos = master_row.find("HB LOCAL")
            if local_pos >= 0:
                heartbeat_overlays.append((master_row, [(local_pos, "HB LOCAL", 4)]))

            compact_hb_colors = {"fresh": 4, "warning": 5, "stale": 6, "unknown": 5}
            for index, worker in enumerate(visible_workers):
                status = str(worker.get("mesh_status") or "UNKNOWN")
                symbol = _mesh_node_symbol(status, pulse_on)
                branch = "└─" if index == len(visible_workers) - 1 else "├─"
                hb_label, hb_state = _heartbeat_display(worker.get("last_seen"))
                row = (
                    f"{branch}{symbol} {str(worker.get('hostname') or 'unknown')[:15]:<15} "
                    f"{status:<11} {str(worker.get('ip') or 'no address'):<15} {hb_label}"
                )[:compact_width]
                append(lines, row, 3)
                spans = []
                symbol_pos = row.find(symbol, len(branch))
                status_pos = row.find(status)
                if symbol_pos >= 0:
                    spans.append((symbol_pos, symbol, _mesh_status_color(status)))
                if status_pos >= 0:
                    spans.append((status_pos, status, _mesh_status_color(status)))
                if spans:
                    mesh_overlays.append((row, spans))
                hb_pos = row.find(hb_label)
                if hb_pos >= 0:
                    heartbeat_overlays.append((
                        row, [(hb_pos, hb_label, compact_hb_colors[hb_state])]
                    ))
            if len(workers) > mesh_limit:
                first = worker_offset + 1
                last = worker_offset + len(visible_workers)
                append(lines, f"Workers {first}-{last} of {len(workers)} — PgUp/PgDn mesh"[:compact_width], 3)

            # Master status is local-only here; fleet problems do not make the
            # Master itself look degraded.
            append(lines, compact_heading("MASTER DETAILS"), 3)
            network_detail = f"{_state_icon(network_state)} {network_word}"
            daemon_state = "healthy" if current.daemon_status == "running" else "degraded"
            daemon_detail = f"{_state_icon(daemon_state)} {daemon_word}"
            master_detail = (
                f"Health {master_health_word}   "
                f"Network {network_detail}   "
                f"Daemon {daemon_detail}"
            )[:compact_width]
            append(lines, master_detail, 3)
            detail_spans = []
            for span, color_number in (
                (master_health_word, _mesh_status_color(master_mesh_status)),
                (network_detail, 4 if network_state == "healthy" else 5 if network_state == "degraded" else 3),
                (daemon_detail, 4 if daemon_state == "healthy" else 6),
            ):
                pos = master_detail.find(span)
                if pos >= 0:
                    detail_spans.append((pos, span, color_number))
            if detail_spans:
                detail_overlays.append((master_detail, detail_spans))

            # Show the Master plus the workers on the current mesh page.
            append(lines, compact_heading("NODE CONNECTIONS"), 3)
            append(
                lines,
                f"{'':16}{'FILE/MOUNT':<14}{'SHELL':<12}{'ADMIN':<10}BACKUP"[:compact_width],
                3,
            )
            visible_hosts = {
                current.master_hostname,
                *(str(worker.get("hostname") or "unknown") for worker in visible_workers),
            }
            compact_access_rows = [
                row for row in node_access_rows
                if str(row.get("hostname") or "unknown") in visible_hosts
            ]
            if not compact_access_rows:
                compact_access_rows = [{
                    "hostname": current.master_hostname, "file": "UNKNOWN", "file_ok": False,
                    "shell": "UNKNOWN", "shell_ok": False, "admin": "UNKNOWN", "admin_ok": False,
                }]
                compact_access_rows.extend({
                    "hostname": str(worker.get("hostname") or "unknown"),
                    "file": "UNKNOWN", "file_ok": False,
                    "shell": "UNKNOWN", "shell_ok": False,
                    "admin": "UNKNOWN", "admin_ok": False,
                } for worker in visible_workers)
            for access in compact_access_rows:
                file_icon = "●" if access.get("file_ok") else "✗"
                shell_icon = "●" if access.get("shell_ok") else "✗"
                admin_icon = "●" if access.get("admin_ok") else "✗"
                file_text = f"{file_icon} {str(access.get('file') or 'UNKNOWN')}"
                shell_text = f"{shell_icon} {str(access.get('shell') or 'UNKNOWN')}"
                admin_text = f"{admin_icon} {str(access.get('admin') or 'UNKNOWN')}"
                hostname = str(access.get("hostname") or "unknown")
                backup = backup_by_hostname.get(
                    hostname,
                    {"label": "NOT SET UP", "ok": False, "state": "not_set_up"},
                )
                backup_icon = "●" if backup.get("ok") else "○"
                backup_text = f"{backup_icon} {str(backup.get('label') or 'UNKNOWN')}"
                row_ok = bool(
                    access.get("file_ok") and access.get("shell_ok") and access.get("admin_ok")
                    and backup.get("ok")
                )
                connection_row = (
                    f"{hostname[:14]:<16}"
                    f"{file_text:<14}{shell_text:<12}{admin_text:<10}{backup_text}"
                )[:compact_width]
                append(lines, connection_row, 4 if row_ok else 5)

            # Recent Logs consume only the rows still available.  A short compact
            # terminal may show 1-2 events; taller compact terminals show up to 5.
            append(lines, compact_heading("RECENT LOGS"), 3)
            compact_body_capacity = max(0, render_height - 3)
            problem_rows = current.problems[:5]
            reserved_problem_rows = (1 + len(problem_rows)) if problem_rows else 0
            log_slots = max(0, compact_body_capacity - len(lines) - reserved_problem_rows)
            if current.events and log_slots:
                for event in current.events[:min(5, log_slots)]:
                    row, color = _recent_log_row(event, compact_width)
                    append(lines, row, color)
            elif not current.events and log_slots:
                append(lines, "○ No recent Lattice events"[:compact_width], 3)

            if problem_rows and len(lines) < compact_body_capacity:
                append(lines, compact_heading("RECENT PROBLEMS"), 3)
                problem_slots = max(0, compact_body_capacity - len(lines))
                for problem in problem_rows[:problem_slots]:
                    row, color, overlay = _recent_problem_row(problem, compact_width)
                    append(lines, row, color)
                    if overlay is not None:
                        problem_overlays.append((row, [overlay]))

        # Full mode pins controls to its canvas bottom; compact mode keeps them dense.
        full_labels = ["Add Computer", "Remove Computer", "Backups", "Settings", "Health Check", "FIX", "Reset Lattice", "Exit", "Care"]
        compact_labels = ["Add", "Rm", "Bkp", "Set", "Health", "Fix", "Reset", "Exit", "Care"]
        def action_text(index: int, compact: bool = False) -> str:
            marker = ">" if selected == index else " "
            gap = "" if compact else " "
            labels = compact_labels if compact else full_labels
            return f"{marker}[{index + 1}]{gap}{labels[index]}"

        if mode == "full":
            footer_lines = [
                (section_sep, curses.color_pair(1)),
                (" ".join(action_text(i) for i in range(4)), curses.color_pair(3)),
                (" ".join(action_text(i) for i in range(4, 9)), curses.color_pair(3)),
                ("[V] Verify Fleet & Clear Resolved", curses.color_pair(3)),
                ("↑/↓ Select  Enter Open  K/J Scroll  PgUp/PgDn Mesh  Q Exit", curses.color_pair(3)),
            ]
        else:
            footer_lines = [
                (section_sep, curses.color_pair(1)),
                ("".join(action_text(i, compact=True) for i in range(9)), curses.color_pair(3)),
                ("[V] Verify Fleet   ↑/↓ Select   Enter Open   Q Exit", curses.color_pair(3)),
            ]

        body_capacity = max(0, render_height - len(footer_lines))
        if mode == "full":
            max_view_offset = max(0, len(lines) - body_capacity)
            view_offset = min(max(0, view_offset), max_view_offset)
            visible_lines = lines[view_offset:view_offset + body_capacity]
        else:
            view_offset = 0
            while len(lines) > body_capacity:
                # Compact mode remains dense and non-scrollable: collapse only
                # decorative/secondary rows, preserving its existing behavior.
                removable = next((i for i in range(len(lines) - 1, -1, -1) if lines[i][0] == ""), None)
                if removable is None:
                    removable = next((
                        i for i, item in enumerate(lines)
                        if item[0].startswith("Last Scan")
                        or item[0].startswith("Uptime      ")
                        or item[0].startswith("+ ")
                        or "WAITING TO PAIR" in item[0]
                    ), None)
                if removable is None:
                    break
                lines.pop(removable)
            max_view_offset = 0
            visible_lines = lines[:body_capacity]
        for y, (text, color) in enumerate(visible_lines):
            _safe_addstr(stdscr, y_offset + y, x_offset, text.ljust(panel_width), color)

        # Mesh status/dots and heartbeat ages can share rows, so overlay each
        # independently colored span after the neutral row has been drawn.
        for overlay_line, spans in mesh_overlays + heartbeat_overlays + detail_overlays + problem_overlays:
            for y, (text, _color) in enumerate(visible_lines):
                if text != overlay_line:
                    continue
                for rel_x, span, color_number in spans:
                    if rel_x >= 0:
                        _safe_addstr(
                            stdscr, y_offset + y, x_offset + rel_x, span,
                            curses.color_pair(color_number),
                        )
                break

        if mode == "full":
            footer_start = y_offset + max(0, render_height - len(footer_lines))
        else:
            # Compact mode is intentionally a dense card: keep controls directly
            # below the visible content instead of leaving a large empty middle.
            footer_start = y_offset + min(
                len(visible_lines), max(0, render_height - len(footer_lines))
            )
        for offset, (text, color) in enumerate(footer_lines):
            _safe_addstr(stdscr, footer_start + offset, x_offset, text.ljust(panel_width), color)

        stdscr.refresh()
        key = stdscr.getch()
        if key == -1 or key == curses.KEY_RESIZE:
            continue
        if mode == "full" and key in (ord('k'), ord('K')):
            view_offset = max(0, view_offset - 1)
            continue
        if mode == "full" and key in (ord('j'), ord('J')):
            view_offset = min(max_view_offset, view_offset + 1)
            continue
        if mode == "full" and key == curses.KEY_HOME:
            view_offset = 0
            continue
        if mode == "full" and key == curses.KEY_END:
            view_offset = max_view_offset
            continue
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(menu_items)
            continue
        if key == curses.KEY_DOWN:
            selected = (selected + 1) % len(menu_items)
            continue
        if key == curses.KEY_PPAGE:
            worker_offset = max(0, worker_offset - max(1, mesh_limit))
            continue
        if key == curses.KEY_NPAGE:
            worker_offset = min(max_worker_offset, worker_offset + max(1, mesh_limit))
            continue

        if key in (ord('v'), ord('V')):
            _fleet_verify_clear_flow(stdscr, status_loader)
            if status_loader is not None:
                try:
                    current = status_loader()
                    status_error = None
                except Exception as exc:
                    status_error = str(exc)
            last_status_refresh = time.monotonic()
            continue

        direct = None
        if ord('1') <= key <= ord('9'):
            direct = key - ord('1')
            selected = direct
        if key in (ord('q'), ord('Q')):
            return 7
        if key in (ord('\n'), ord('\r'), curses.KEY_ENTER) or direct is not None:
            if selected == 7:
                return selected
            if selected == 0:
                _add_worker_flow(stdscr, discovery_monitor)
            elif selected == 1:
                _remove_worker_flow(stdscr)
            elif selected == 2:
                _backups_flow(stdscr)
            elif selected == 3:
                _settings_flow(stdscr)
            elif selected == 4:
                _health_check_flow(stdscr, current, status_loader)
            elif selected == 5:
                _fix_flow(stdscr, current, status_loader)
            elif selected == 6:
                if _reset_lattice_flow(stdscr):
                    return 7
            elif selected == 8:
                _master_care_flow(stdscr, current, status_loader)
            if status_loader is not None:
                try:
                    current = status_loader()
                    status_error = None
                except Exception as exc:
                    status_error = str(exc)
            last_status_refresh = time.monotonic()
            continue

# ---- Main entry point ----
def run_tui(status: LatticeStatus) -> int:
    monitor = DiscoveryMonitor() if status.role == "master" else None
    if monitor is not None:
        monitor.start()
    try:
        return curses.wrapper(show_re_run_menu, status, monitor, get_status)
    finally:
        if monitor is not None:
            monitor.stop()
