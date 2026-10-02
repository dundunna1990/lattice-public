"""
Event and alert storage with deduplication.
"""
import asyncio
import functools
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from lattice.core.db import get_db_connection
from lattice.notifications.manager import get_manager

logger = logging.getLogger(__name__)


def log_event(worker_id: Optional[int], event_type: str, severity: str, message: str, details: Optional[Dict] = None) -> int:
    """
    Log an event to the events table.
    Returns the event ID.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO events (timestamp, worker_id, type, severity, message, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (datetime.now(timezone.utc).isoformat(), worker_id, event_type, severity, message, json.dumps(details) if details else None)
    )
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    logger.debug(f"Event logged: {event_type} ({severity}) for worker {worker_id}: {message}")
    return event_id

def create_alert(worker_id: Optional[int], severity: str, title: str, message: str, trigger_event_id: int) -> Optional[int]:
    """
    Create an alert if a duplicate doesn't already exist within the dedup window.
    Returns the alert ID, or None if dedup'd.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Serialize check+insert so concurrent reporters cannot create twins.
    # An unresolved alert remains the canonical incident regardless of age.
    cursor.execute("BEGIN IMMEDIATE")
    if worker_id is None:
        cursor.execute(
            """
            SELECT id FROM alerts
            WHERE worker_id IS NULL AND title = ? AND resolved_at IS NULL
            ORDER BY id LIMIT 1
            """,
            (title,),
        )
    else:
        cursor.execute(
            """
            SELECT id FROM alerts
            WHERE worker_id = ? AND title = ? AND resolved_at IS NULL
            ORDER BY id LIMIT 1
            """,
            (worker_id, title),
        )
    existing = cursor.fetchone()
    if existing:
        conn.rollback()
        conn.close()
        logger.info(f"Alert dedup'd: {title} for worker {worker_id} (existing alert {existing[0]})")
        return None

    # Create new alert
    cursor.execute(
        """
        INSERT INTO alerts (worker_id, severity, title, message, trigger_event_id, fired_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (worker_id, severity, title, message, trigger_event_id, datetime.now(timezone.utc).isoformat())
    )
    alert_id = cursor.lastrowid
    # Q12 fix: reuse the existing conn (don't open a 2nd for the lookup)
    hostname = None
    if worker_id is not None:
        worker_cursor = conn.cursor()
        worker_cursor.execute("SELECT hostname FROM workers WHERE id = ?", (worker_id,))
        worker_row = worker_cursor.fetchone()
        hostname = worker_row[0] if worker_row else None
    # M1 fix: COMMIT FIRST. If commit fails, no notification is sent for a
    # phantom alert. This prevents spurious Telegram messages when the DB
    # write fails.
    conn.commit()
    conn.close()
    # Now send the notification (only after commit succeeded).
    #
    # Notification channels currently expose a synchronous interface and may
    # perform network I/O. If create_alert() is reached from an asyncio runtime
    # path, dispatch delivery to the executor rather than blocking the master
    # event loop. Synchronous CLI/test callers retain synchronous semantics.
    if hostname:
        manager = get_manager()
        notify = functools.partial(
            manager.send,
            title,
            message,
            severity=severity,
            alert_id=alert_id,
            worker=hostname,
        )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            notify()
        else:
            loop.run_in_executor(None, notify)

    logger.info(f"Alert created: {title} (severity {severity}) for worker {worker_id}")
    return alert_id

def resolve_alert(alert_id: int, resolution_event_id: Optional[int] = None) -> bool:
    """Resolve an active alert."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE alerts SET resolved_at = ?, resolution_event_id = ? WHERE id = ? AND resolved_at IS NULL
        """,
        (datetime.now(timezone.utc).isoformat(), resolution_event_id, alert_id)
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    if affected:
        logger.info(f"Alert {alert_id} resolved")
    else:
        logger.warning(f"Alert {alert_id} not found or already resolved")
    return affected > 0

def get_active_alerts(worker_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Get all active alerts, optionally filtered by worker."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if worker_id is not None:
        cursor.execute(
            """
            SELECT a.id, a.severity, a.title, a.message, a.fired_at,
                   a.worker_id, w.hostname
            FROM alerts a
            LEFT JOIN workers w ON w.id = a.worker_id
            WHERE a.worker_id = ? AND a.resolved_at IS NULL
            ORDER BY a.fired_at DESC
            """,
            (worker_id,)
        )
    else:
        cursor.execute(
            """
            SELECT a.id, a.severity, a.title, a.message, a.fired_at,
                   a.worker_id, w.hostname
            FROM alerts a
            LEFT JOIN workers w ON w.id = a.worker_id
            WHERE a.resolved_at IS NULL
            ORDER BY a.fired_at DESC
            """
        )
    rows = cursor.fetchall()
    conn.close()
    return [
        {
            "id": r[0],
            "severity": r[1],
            "title": r[2],
            "message": r[3],
            "fired_at": r[4],
            "worker_id": r[5],
            # A missing worker means this is a master-side alert, rather than
            # leaving a confusing blank computer name in the dashboard.
            "worker": r[6] or "Master",
        }
        for r in rows
    ]

def acknowledge_alert(alert_id: int) -> bool:
    """Mark an alert as acknowledged (seen by the user)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE alerts SET acked_at = datetime('now') WHERE id = ? AND resolved_at IS NULL",
        (alert_id,)
    )
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    if affected:
        logger.info(f"Alert {alert_id} acknowledged")
    else:
        logger.warning(f"Alert {alert_id} not found or already resolved")
    return affected > 0


def resolve_worker_alerts_after_recovery(worker_id: int) -> int:
    """Resolve only repair/protected alerts proven stale by a healthy worker check."""
    conn = get_db_connection()
    try:
        active = conn.execute(
            """
            SELECT COUNT(*)
            FROM alerts a
            JOIN events e ON e.id = a.trigger_event_id
            WHERE a.worker_id = ? AND a.resolved_at IS NULL
              AND e.type IN ('autoheal.detected', 'autoheal.failed', 'autoheal.protected_issue')
            """,
            (worker_id,),
        ).fetchone()[0]
    finally:
        conn.close()
    if not active:
        return 0
    resolution_event_id = log_event(
        worker_id,
        "recovery.verified",
        "ok",
        "Lattice verified that this worker recovered.",
    )
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """
            UPDATE alerts AS a
            SET resolved_at = ?, resolution_event_id = ?
            WHERE a.worker_id = ? AND a.resolved_at IS NULL
              AND EXISTS (
                  SELECT 1 FROM events e
                  WHERE e.id = a.trigger_event_id
                    AND e.type IN ('autoheal.detected', 'autoheal.failed', 'autoheal.protected_issue')
              )
            """,
            (datetime.now(timezone.utc).isoformat(), resolution_event_id, worker_id),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def sync_network_reconcile_alert(worker_id: int | None, hostname: str, state: str) -> int | None:
    """Keep exactly one active alert for an unrecoverable Worker network state."""
    hard_failure = state in {"unsafe_network", "repair_failed"}
    recovered = state in {"healthy", "repaired"}
    if not hard_failure and not recovered:
        return None
    title = f"Network self-heal needs attention: {hostname}"
    conn = get_db_connection()
    try:
        if worker_id is None:
            row = conn.execute(
                """SELECT a.id FROM alerts a JOIN events e ON e.id=a.trigger_event_id
                   WHERE a.worker_id IS NULL AND a.title=? AND a.resolved_at IS NULL
                     AND e.type='network.reconcile_failed' ORDER BY a.id DESC LIMIT 1""",
                (title,),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT a.id FROM alerts a JOIN events e ON e.id=a.trigger_event_id
                   WHERE a.worker_id=? AND a.title=? AND a.resolved_at IS NULL
                     AND e.type='network.reconcile_failed' ORDER BY a.id DESC LIMIT 1""",
                (worker_id, title),
            ).fetchone()
    finally:
        conn.close()
    if hard_failure and row is not None:
        return int(row[0])
    if recovered and row is None:
        return None
    if hard_failure:
        event_id = log_event(
            worker_id,
            "network.reconcile_failed",
            "error",
            f"Lattice could not safely restore the expected network address on {hostname}.",
            {"state": state},
        )
        return create_alert(
            worker_id,
            "error",
            title,
            "Automatic network repair stopped because a safety check failed. Lattice left networking unchanged or rolled it back.",
            event_id,
        )

    resolution_event_id = log_event(
        worker_id,
        "network.reconcile_recovered",
        "ok",
        f"Lattice verified network recovery on {hostname}.",
        {"state": state},
    )
    resolve_alert(int(row[0]), resolution_event_id)
    return int(row[0])


def sync_master_self_check_alert(
    component: str,
    error: str | None,
    *,
    severity: str = "warn",
) -> int | None:
    """Keep one active alert per Master self-check component."""
    if component not in {"db", "socket", "audit_log"}:
        raise ValueError("Unknown Master self-check component")
    if severity not in {"warn", "error"}:
        raise ValueError("Unknown Master self-check severity")

    title = f"Lattice master self-check: {component}"
    detected_type = (
        "audit.capacity"
        if component == "audit_log"
        else "autoheal.master_detected"
    )
    recovered_type = (
        "audit.capacity_recovered"
        if component == "audit_log"
        else "autoheal.master_recovered"
    )

    if error is not None:
        event_id = log_event(
            None, detected_type, severity,
            f"Master self-check failed: {component}: {error}",
            {"component": component},
        )
        existing = _active_master_alert_id(title)
        message = (
            f"The Master {component} self-check needs attention. "
            f"Lattice will keep checking automatically: {error}"
        )
        if existing is not None:
            # Keep one incident, but allow a capacity warning to escalate.
            conn = get_db_connection()
            try:
                conn.execute(
                    "UPDATE alerts SET severity=?, message=? "
                    "WHERE id=? AND resolved_at IS NULL",
                    (severity, message, existing),
                )
                conn.commit()
            finally:
                conn.close()
            return existing
        created = create_alert(
            None, severity, title, message, event_id,
        )
        return created or _active_master_alert_id(title)

    alert_id = _active_master_alert_id(title)
    if alert_id is None:
        return None
    event_id = log_event(
        None, recovered_type, "ok",
        f"Master self-check recovered: {component}",
        {"component": component},
    )
    resolve_alert(alert_id, event_id)
    return alert_id


def _active_master_alert_id(title: str) -> int | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id FROM alerts WHERE worker_id IS NULL AND title=? AND resolved_at IS NULL ORDER BY id LIMIT 1",
            (title,),
        ).fetchone()
        return int(row[0]) if row is not None else None
    finally:
        conn.close()


def resolve_legacy_master_self_check_alerts() -> int:
    """Resolve historical duplicate self-check alerts after all checks are green."""
    conn = get_db_connection()
    try:
        count = conn.execute(
            """SELECT COUNT(*) FROM alerts a JOIN events e ON e.id=a.trigger_event_id
               WHERE a.worker_id IS NULL AND a.resolved_at IS NULL
                 AND e.type='autoheal.master_detected'"""
        ).fetchone()[0]
    finally:
        conn.close()
    if not count:
        return 0
    event_id = log_event(
        None, "autoheal.master_recovered", "ok",
        "Lattice verified that all Master self-checks are healthy.",
    )
    conn = get_db_connection()
    try:
        cur = conn.execute(
            """UPDATE alerts AS a SET resolved_at=?, resolution_event_id=?
               WHERE a.worker_id IS NULL AND a.resolved_at IS NULL
                 AND EXISTS (SELECT 1 FROM events e WHERE e.id=a.trigger_event_id
                             AND e.type='autoheal.master_detected')""",
            (datetime.now(timezone.utc).isoformat(), event_id),
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
