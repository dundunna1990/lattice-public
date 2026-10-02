"""
Worker state machine (Section 4 of the plan).
Manages worker health states: Unknown, Healthy, Degraded, Down, Disabled.
"""
import enum
import logging
from datetime import datetime, timedelta
from typing import Optional

from lattice.core.db import get_db_connection, is_sqlite_busy_error
from lattice.core.events import log_event

logger = logging.getLogger(__name__)

class WorkerState(enum.Enum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    CONFIGURING = "configuring"
    NEEDS_ATTENTION = "needs_attention"
    DISABLED = "disabled"

# Configuration for transition thresholds (per plan)
MARK_DOWN_AFTER_FAILURES = 3   # consecutive failures


def heartbeat_worker_target_state(
    current_status: str,
    failure_count: int,
    heartbeat_status: str,
) -> WorkerState:
    """Merge a trusted heartbeat without overriding master reachability.

    Rules:
    - heartbeat may lower healthy/unknown -> degraded
    - heartbeat may clear service-only degraded -> healthy only when the
      master has zero outstanding reachability failures
    - heartbeat never clears DOWN
    - heartbeat never changes DISABLED
    - heartbeat never creates DOWN
    """
    current = WorkerState(current_status)
    failures = failure_count or 0

    if current in {
        WorkerState.DOWN,
        WorkerState.CONFIGURING,
        WorkerState.NEEDS_ATTENTION,
        WorkerState.DISABLED,
    }:
        return current

    if heartbeat_status == "degraded":
        return WorkerState.DEGRADED

    if heartbeat_status == "healthy":
        if current == WorkerState.DEGRADED and failures == 0:
            return WorkerState.HEALTHY
        if current == WorkerState.HEALTHY:
            return WorkerState.HEALTHY

    return current


def update_worker_state(
    worker_id: int,
    is_healthy: bool,
    _retry: int = 0,
    service_degraded: bool = False,
) -> WorkerState:
    """
    Update the state of a worker based on a health check result.
    Returns the new state.

    Uses BEGIN IMMEDIATE so the SELECT-then-UPDATE is atomic against concurrent
    writers (other health checks firing in parallel during a network blip).
    Retries on SQLITE_BUSY up to 3 times with a short backoff.
    """
    import time as _time
    import sqlite3 as _sqlite3
    conn = get_db_connection()
    try:
        # BEGIN IMMEDIATE acquires a RESERVED lock at the start of the transaction,
        # so two concurrent health checks can't both read the same row and
        # double-increment failure_count.
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT status, failure_count FROM workers WHERE id = ?",
            (worker_id,)
        )
        row = cursor.fetchone()
        if not row:
            conn.execute("ROLLBACK")
            raise ValueError(f"Worker {worker_id} not found")
        current_status, failure_count = row

        protected_states = {
            WorkerState.CONFIGURING,
            WorkerState.NEEDS_ATTENTION,
            WorkerState.DISABLED,
        }
        current_state = WorkerState(current_status)
        if current_state in protected_states:
            # Reachability alone must never complete or erase an interrupted
            # pairing/configuration transaction. Only that workflow may move
            # these states forward.
            conn.execute("ROLLBACK")
            return current_state

        new_state = None
        failure_count = failure_count or 0

        if is_healthy:
            # A successful master-side API check proves reachability and clears
            # connectivity failures. Fresh authenticated service evidence can
            # still keep the worker degraded.
            failure_count = 0
            target_state = (
                WorkerState.DEGRADED
                if service_degraded
                else WorkerState.HEALTHY
            )
            if current_status != target_state.value:
                new_state = target_state
        else:
            failure_count += 1
            if failure_count >= MARK_DOWN_AFTER_FAILURES:
                new_state = WorkerState.DOWN
            else:
                new_state = WorkerState.DEGRADED

        if new_state is None:
            conn.execute("ROLLBACK")
            return WorkerState(current_status)

        cursor.execute(
            "UPDATE workers SET status = ?, failure_count = ? WHERE id = ?",
            (new_state.value, failure_count, worker_id)
        )
        conn.execute("COMMIT")

        logger.info(f"Worker {worker_id} state changed: {current_status} -> {new_state.value}")
        return new_state
    except Exception as exc:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        if is_sqlite_busy_error(exc) and _retry < 3:
            _time.sleep(0.05 * (2 ** _retry))
            return update_worker_state(
                worker_id,
                is_healthy,
                _retry=_retry + 1,
                service_degraded=service_degraded,
            )
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def get_worker_state(worker_id: int) -> WorkerState:
    """Retrieve the current state of a worker."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM workers WHERE id = ?", (worker_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise ValueError(f"Worker {worker_id} not found")
    return WorkerState(row[0])

def set_worker_disabled(worker_id: int, disabled: bool) -> None:
    """Enable or disable a worker (operator control)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    new_state = WorkerState.DISABLED if disabled else WorkerState.UNKNOWN
    cursor.execute(
        "UPDATE workers SET status = ? WHERE id = ?",
        (new_state.value, worker_id)
    )
    conn.commit()
    conn.close()
    logger.info(f"Worker {worker_id} {'disabled' if disabled else 'enabled'}")
