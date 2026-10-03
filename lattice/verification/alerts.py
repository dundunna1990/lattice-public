"""Read-only recovery verdicts for active Lattice alerts."""
from __future__ import annotations

import json

from lattice.core.db import get_db_connection
from lattice.verification.backup import backup_alert_recovery


def _details(value: object) -> dict:
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _node_for_alert(row, reports: dict[str, dict]) -> dict | None:
    hostname = str(row["hostname"] or "")
    if hostname and hostname in reports:
        return reports[hostname]
    if row["worker_id"] is None:
        return next((item for item in reports.values() if item.get("role") == "master"), None)
    return None


def _mount_recovered(details: dict) -> tuple[bool | None, str]:
    peer = details.get("peer_node_id")
    if not isinstance(peer, str) or not peer:
        return None, "file-access alert has no peer Node ID"
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT state FROM mount_state WHERE peer_node_id=?", (peer,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None, "current mount state is unavailable"
    return str(row["state"]) in {"mounted", "paused"}, f"mount state is {row['state']}"


def _shell_recovered(details: dict) -> tuple[bool | None, str]:
    peer = details.get("peer_node_id")
    if not isinstance(peer, str) or not peer:
        return None, "shell alert has no peer Node ID"
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT state FROM shell_connection_state WHERE peer_node_id=?",
            (peer,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None, "current trusted-shell state is unavailable"
    return str(row["state"]) == "connected", f"trusted-shell state is {row['state']}"


def _rotation_recovered(table: str, alert_id: int, details: dict) -> tuple[bool | None, str]:
    target = details.get("target_node_id")
    if not isinstance(target, str) or not target:
        return None, "key-rotation alert has no target Node ID"
    if table not in {"file_key_rotations", "shell_key_rotations"}:
        return None, "invalid rotation verifier table"
    conn = get_db_connection()
    try:
        row = conn.execute(
            f"SELECT alert_id,stage FROM {table} WHERE target_node_id=?",
            (target,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return True, "key-rotation state has completed and been retired"
    if row["alert_id"] is None or int(row["alert_id"]) != int(alert_id):
        return True, "this alert no longer owns the active key-rotation state"
    return False, f"key rotation is still in stage {row['stage']}"


def _event_recovery(row, reports: dict[str, dict]) -> tuple[bool | None, str]:
    event_type = str(row["event_type"] or "")
    details = _details(row["details"])
    if event_type.startswith("backup."):
        return backup_alert_recovery(event_type, details)
    if event_type == "file_access.mount_persistent":
        return _mount_recovered(details)
    if event_type == "shell_access.connection_persistent":
        return _shell_recovered(details)
    if event_type == "file_access.key_rotation_stalled":
        return _rotation_recovered("file_key_rotations", int(row["id"]), details)
    if event_type == "shell_access.key_rotation_stalled":
        return _rotation_recovered("shell_key_rotations", int(row["id"]), details)

    node = _node_for_alert(row, reports)
    if event_type in {"autoheal.detected", "autoheal.failed", "autoheal.protected_issue"}:
        if node is None:
            return None, "affected node verification is unavailable"
        return node.get("status") == "healthy", "affected node live health rechecked"
    if event_type == "network.reconcile_failed":
        if node is None:
            return None, "affected node verification is unavailable"
        return node.get("network_state") == "healthy", "network reconciliation state rechecked"
    if event_type == "autoheal.master_detected":
        if node is None:
            return None, "Master verification is unavailable"
        component = str(details.get("component") or "")
        value = dict(node.get("core") or {}).get(component)
        return value == "healthy", f"Master {component or 'self-check'} state rechecked"
    if event_type == "audit.capacity":
        if node is None:
            return None, "Master verification is unavailable"
        size = dict(node.get("core") or {}).get("audit_log_bytes")
        if not isinstance(size, int):
            return None, "Master audit-log evidence is unavailable"
        from lattice.core.self_check import AUDIT_WARN_BYTES
        return size < AUDIT_WARN_BYTES, "Master audit-log capacity rechecked"
    return None, f"no recovery verifier is registered for alert event {event_type or 'unknown'}"


def evaluate_active_alerts(reports: dict[str, dict]) -> list[dict]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT a.id,a.worker_id,a.severity,a.title,a.message,a.fired_at,
                      e.type AS event_type,e.details,w.hostname
               FROM alerts a
               JOIN events e ON e.id=a.trigger_event_id
               LEFT JOIN workers w ON w.id=a.worker_id
               WHERE a.resolved_at IS NULL
               ORDER BY a.id"""
        ).fetchall()
    finally:
        conn.close()

    result: list[dict] = []
    for row in rows:
        recovered, reason = _event_recovery(row, reports)
        verdict = "resolved" if recovered is True else ("active" if recovered is False else "unknown")
        result.append({
            "id": int(row["id"]),
            "worker_id": row["worker_id"],
            "worker": str(row["hostname"] or "Master"),
            "severity": str(row["severity"]),
            "title": str(row["title"]),
            "event_type": str(row["event_type"] or ""),
            "verdict": verdict,
            "reason": reason,
        })
    return result
