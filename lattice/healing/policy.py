"""The small, explicit policy governing unattended Lattice healing."""

from datetime import datetime, timedelta, timezone

from lattice.core.db import get_db_connection


MODE_ALERT_ONLY = "alert_only"
MODE_AUTOMATIC = "automatic"
APPROVED_RESTART_SERVICES = {"lattice-master", "lattice-worker"}
MAX_RESTART_ATTEMPTS = 2
RESTART_WINDOW = timedelta(minutes=15)


def normalize_service(service):
    value = service.strip().lower()
    return value[:-8] if value.endswith(".service") else value


def is_approved_restart_service(service):
    return normalize_service(service) in APPROVED_RESTART_SERVICES


def restart_budget_available(worker_id, service, now=None):
    """Return whether fewer than two restart attempts happened in 15 minutes."""
    now = now or datetime.now(timezone.utc)
    cutoff = (now - RESTART_WINDOW).isoformat()
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) FROM healing_attempts
            WHERE worker_id = ? AND service = ? AND action = 'restart'
            AND started_at >= ?
            """,
            (worker_id, normalize_service(service), cutoff),
        ).fetchone()
        return row[0] < MAX_RESTART_ATTEMPTS
    finally:
        conn.close()


def record_restart_attempt(worker_id, service, result="started", now=None):
    now = now or datetime.now(timezone.utc)
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO healing_attempts (worker_id, service, action, started_at, result)
            VALUES (?, ?, 'restart', ?, ?)
            """,
            (worker_id, normalize_service(service), now.isoformat(), result),
        )
        conn.commit()
    finally:
        conn.close()


def reserve_restart_attempt(worker_id, service, result="started", now=None):
    """Atomically reserve one restart slot inside the rolling safety budget.

    BEGIN IMMEDIATE serializes competing writers before the count is read,
    preventing two tasks/processes from both observing the same free slot.
    """
    now = now or datetime.now(timezone.utc)
    normalized = normalize_service(service)
    cutoff = (now - RESTART_WINDOW).isoformat()

    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")

        count = conn.execute(
            """
            SELECT COUNT(*)
            FROM healing_attempts
            WHERE worker_id = ?
              AND service = ?
              AND action = 'restart'
              AND started_at >= ?
            """,
            (worker_id, normalized, cutoff),
        ).fetchone()[0]

        if count >= MAX_RESTART_ATTEMPTS:
            conn.rollback()
            return False

        conn.execute(
            """
            INSERT INTO healing_attempts (
                worker_id,
                service,
                action,
                started_at,
                result
            )
            VALUES (?, ?, 'restart', ?, ?)
            """,
            (
                worker_id,
                normalized,
                now.isoformat(),
                result,
            ),
        )

        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
