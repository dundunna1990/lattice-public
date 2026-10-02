"""Strict read-only data surface for the local Lattice operator CLI."""
from __future__ import annotations

from datetime import datetime, timezone
import uuid

from lattice.core.db import get_db_connection

BACKUP_OBSERVATION_STALE_SECONDS = 60


class OperatorRequestError(ValueError):
    """Raised when a read-only operator request is invalid or unsupported."""


def _bounded_int(value, *, default: int, low: int = 1, high: int = 200) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise OperatorRequestError("Numeric parameter is invalid")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise OperatorRequestError("Numeric parameter is invalid") from exc
    if not low <= parsed <= high:
        raise OperatorRequestError(f"Numeric parameter must be between {low} and {high}")
    return parsed


def _positive_id(value, label: str) -> int:
    parsed = _bounded_int(value, default=1, high=2_147_483_647)
    if parsed < 1:
        raise OperatorRequestError(f"{label} is invalid")
    return parsed


def _node_id(value) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise OperatorRequestError("Peer Node ID is invalid") from exc
    if parsed.version != 4:
        raise OperatorRequestError("Peer Node ID must be UUIDv4")
    return str(parsed)


def _hostname(value) -> str:
    if not isinstance(value, str) or not value or len(value) > 253 or "\x00" in value:
        raise OperatorRequestError("Hostname is invalid")
    return value


def _status() -> dict:
    from lattice.cli.tui import get_status

    status = get_status()
    return {
        "role": status.role,
        "master_hostname": status.master_hostname,
        "master_ip": status.master_ip,
        "daemon_status": status.daemon_status,
        "uptime": status.uptime,
        "version": status.version,
        "workers": list(status.workers),
        "alerts": list(status.alerts),
        "health": dict(status.health),
        "events": list(status.events),
    }


def _workers_list() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT w.hostname, w.status, w.last_heartbeat_at, w.failure_count,
                      w.ip, fn.node_id
               FROM workers AS w
               LEFT JOIN fleet_nodes AS fn
                 ON fn.worker_id=w.id AND fn.membership_state='active'
               WHERE w.removed_at IS NULL
               ORDER BY w.hostname COLLATE NOCASE
               LIMIT 64"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _workers_get(hostname: str) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT w.hostname, w.status, w.ip, w.ssh_user,
                      w.last_heartbeat_at, w.failure_count, fn.node_id
               FROM workers AS w
               LEFT JOIN fleet_nodes AS fn
                 ON fn.worker_id=w.id AND fn.membership_state='active'
               WHERE w.hostname=? AND w.removed_at IS NULL
               LIMIT 1""",
            (_hostname(hostname),),
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def _mounts_list() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT ms.peer_node_id, fn.hostname,
                      COALESCE(mp.desired_state, 'mounted') AS desired_state,
                      ms.state, ms.mount_path, ms.failure_count,
                      ms.problem_since, ms.error_code, ms.error_message
               FROM mount_state AS ms
               LEFT JOIN mount_preferences AS mp ON mp.peer_node_id=ms.peer_node_id
               LEFT JOIN fleet_nodes AS fn ON fn.node_id=ms.peer_node_id
               ORDER BY COALESCE(fn.hostname, ms.peer_node_id)
               LIMIT 64"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _mounts_fleet() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT mo.observer_node_id, observer.hostname AS observer_hostname,
                      mo.peer_node_id, peer.hostname AS peer_hostname, mo.state,
                      mo.error_code, mo.last_changed_at, mo.last_reported_at
               FROM mount_observations AS mo
               JOIN fleet_nodes AS observer
                 ON observer.node_id=mo.observer_node_id
                AND observer.membership_state='active'
               JOIN fleet_nodes AS peer
                 ON peer.node_id=mo.peer_node_id
                AND peer.membership_state='active'
               ORDER BY observer.hostname, peer.hostname
               LIMIT 256"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _mounts_get(peer: str) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT ms.peer_node_id, fn.hostname,
                      COALESCE(mp.desired_state, 'mounted') AS desired_state,
                      ms.state, ms.mount_path, ms.failure_count,
                      ms.last_success_at, ms.next_retry_at, ms.problem_since,
                      ms.error_code, ms.error_message
               FROM mount_state AS ms
               LEFT JOIN mount_preferences AS mp ON mp.peer_node_id=ms.peer_node_id
               LEFT JOIN fleet_nodes AS fn ON fn.node_id=ms.peer_node_id
               WHERE ms.peer_node_id=?""",
            (_node_id(peer),),
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def _alerts_list() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT a.id, a.severity, a.title, a.message, a.fired_at,
                      a.worker_id, COALESCE(w.hostname, 'Master') AS worker
               FROM alerts AS a
               LEFT JOIN workers AS w ON w.id=a.worker_id
               WHERE a.resolved_at IS NULL
               ORDER BY a.fired_at DESC
               LIMIT 200"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _alerts_get(alert_id) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT a.id, a.severity, a.title, a.message, a.fired_at,
                      a.worker_id, COALESCE(w.hostname, 'Master') AS worker
               FROM alerts AS a
               LEFT JOIN workers AS w ON w.id=a.worker_id
               WHERE a.id=? LIMIT 1""",
            (_positive_id(alert_id, "Alert ID"),),
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def _shell_status() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT peer_node_id, hostname, state, selected_ip, failure_count,
                      problem_since, last_connected_at, last_disconnected_at
               FROM shell_connection_state
               ORDER BY hostname, peer_node_id
               LIMIT 64"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _shell_history(limit=100) -> list[dict]:
    count = _bounded_int(limit, default=100)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT peer_node_id, hostname, event_type, ip, occurred_at
               FROM shell_connection_history
               ORDER BY id DESC LIMIT ?""",
            (count,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _events(worker=None, limit=50) -> list[dict]:
    count = _bounded_int(limit, default=50)
    conn = get_db_connection()
    try:
        if worker is None:
            rows = conn.execute(
                """SELECT e.timestamp, e.severity, e.message,
                          COALESCE(w.hostname, 'Master') AS worker
                   FROM events AS e
                   LEFT JOIN workers AS w ON w.id=e.worker_id
                   ORDER BY e.id DESC LIMIT ?""",
                (count,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT e.timestamp, e.severity, e.message,
                          COALESCE(w.hostname, 'Master') AS worker
                   FROM events AS e
                   LEFT JOIN workers AS w ON w.id=e.worker_id
                   WHERE w.hostname=?
                   ORDER BY e.id DESC LIMIT ?""",
                (_hostname(worker), count),
            ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()



def _backup_observation_is_stale(value: object, *, now: datetime | None = None) -> bool:
    if not isinstance(value, str) or not value:
        return True
    try:
        reported = datetime.fromisoformat(value)
    except ValueError:
        return True
    if reported.tzinfo is None:
        reported = reported.replace(tzinfo=timezone.utc)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age = (current - reported.astimezone(timezone.utc)).total_seconds()
    return age < -60 or age > BACKUP_OBSERVATION_STALE_SECONDS


def _backups_jobs() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bj.id AS job_id, bj.job_uuid, fn.hostname AS source_hostname,
                      bt.friendly_name AS target_name,
                      CASE WHEN bj.source_node_id=bt.host_node_id
                           THEN 'local_storage' ELSE 'remote_storage' END AS target_type,
                      bj.schedule, bj.paused,
                      bj.pause_reason,
                      COALESCE(bjo.state,
                        CASE WHEN bj.paused=1 THEN 'paused' ELSE 'unknown' END
                      ) AS state,
                      bjo.last_success_at, bjo.last_result, bjo.last_reported_at
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               LEFT JOIN backup_job_observations bjo ON bjo.job_id=bj.id
               WHERE bj.enabled=1
               ORDER BY fn.hostname COLLATE NOCASE, bt.friendly_name COLLATE NOCASE
               LIMIT 128"""
        ).fetchall()
        result = [dict(row) for row in rows]
        for item in result:
            if item.get("last_reported_at") is not None and _backup_observation_is_stale(
                item.get("last_reported_at")
            ):
                item["reported_state"] = item.get("state")
                item["state"] = "unknown"
                item["observation_stale"] = True
            else:
                item["observation_stale"] = False
        return result
    finally:
        conn.close()


def _backups_targets() -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bt.id AS target_id, bt.friendly_name, fn.hostname AS host_hostname,
                      bt.target_type, bt.enabled, bto.present, bto.total_bytes,
                      bto.free_bytes, bto.health, bto.last_reported_at
               FROM backup_targets bt
               JOIN fleet_nodes fn ON fn.node_id=bt.host_node_id
               LEFT JOIN backup_target_observations bto ON bto.target_id=bt.id
               ORDER BY bt.friendly_name COLLATE NOCASE
               LIMIT 128"""
        ).fetchall()
        result = [dict(row) for row in rows]
        for item in result:
            if item.get("last_reported_at") is not None and _backup_observation_is_stale(
                item.get("last_reported_at")
            ):
                item["reported_health"] = item.get("health")
                item["health"] = "unknown"
                item["observation_stale"] = True
            else:
                item["observation_stale"] = False
        return result
    finally:
        conn.close()


def _backups_candidates() -> list[dict]:
    from lattice.backup.catalog import fleet_storage_candidates
    return fleet_storage_candidates(include_sensitive=False)[:128]


def _backups_runs(limit=100) -> list[dict]:
    count = _bounded_int(limit, default=100)
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT br.id AS run_id, fn.hostname AS source_hostname,
                      bt.friendly_name AS target_name, br.started_at, br.finished_at,
                      br.result, br.snapshot_id, br.bytes_added, br.error_code
               FROM backup_runs br
               JOIN backup_jobs bj ON bj.id=br.job_id
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               ORDER BY br.id DESC LIMIT ?""",
            (count,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _backups_summary() -> dict:
    jobs = _backups_jobs()
    counts: dict[str, int] = {}
    for job in jobs:
        state = str(job.get("state") or "unknown")
        counts[state] = counts.get(state, 0) + 1
    return {"jobs": jobs, "state_counts": counts}

def _autoheal_status() -> dict:
    from lattice.core.config import get_config_value
    from lattice.healing.policy import MODE_ALERT_ONLY, MODE_AUTOMATIC

    mode = get_config_value("autoheal.mode")
    mode = MODE_AUTOMATIC if mode == MODE_AUTOMATIC else MODE_ALERT_ONLY
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, hostname FROM workers WHERE removed_at IS NULL ORDER BY hostname COLLATE NOCASE LIMIT 64"
        ).fetchall()
    finally:
        conn.close()
    return {
        "mode": mode,
        "workers": [
            {
                "id": int(row[0]),
                "hostname": str(row[1]),
                "enabled": get_config_value(f"autoheal.enabled.{int(row[0])}") == "true",
            }
            for row in rows
        ],
    }


_COMMANDS = {
    "status": (_status, set()),
    "workers.list": (_workers_list, set()),
    "workers.get": (_workers_get, {"hostname"}),
    "mounts.list": (_mounts_list, set()),
    "mounts.fleet": (_mounts_fleet, set()),
    "mounts.get": (_mounts_get, {"peer"}),
    "alerts.list": (_alerts_list, set()),
    "alerts.get": (_alerts_get, {"alert_id"}),
    "shell.status": (_shell_status, set()),
    "shell.history": (_shell_history, {"limit"}),
    "events": (_events, {"worker", "limit"}),
    "backups.summary": (_backups_summary, set()),
    "backups.jobs": (_backups_jobs, set()),
    "backups.targets": (_backups_targets, set()),
    "backups.candidates": (_backups_candidates, set()),
    "backups.runs": (_backups_runs, {"limit"}),
    "autoheal.status": (_autoheal_status, set()),
}


def execute_operator_request(payload: object) -> dict:
    """Execute exactly one whitelisted read request and return JSON-safe data."""
    if not isinstance(payload, dict) or set(payload) - {"command", "params"}:
        raise OperatorRequestError("Operator request must contain only command and params")
    command = payload.get("command")
    params = payload.get("params", {})
    if not isinstance(command, str) or command not in _COMMANDS:
        raise OperatorRequestError("Operator command is not allowed")
    if not isinstance(params, dict):
        raise OperatorRequestError("Operator params must be an object")
    function, allowed_params = _COMMANDS[command]
    unexpected = set(params) - allowed_params
    if unexpected:
        raise OperatorRequestError("Operator request contains unsupported parameters")
    missing = allowed_params - set(params)
    if command in {"workers.get", "mounts.get", "alerts.get"} and missing:
        raise OperatorRequestError("Operator request is missing a required parameter")
    return {"ok": True, "command": command, "data": function(**params)}
