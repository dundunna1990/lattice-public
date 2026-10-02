"""
2‑signal requirement + identity confidence check (Decision 12).
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone

from lattice.core.db import get_db_connection
from lattice.core.service_status import is_service_healthy

logger = logging.getLogger(__name__)

# Default: require at least 2 independent signals before healing
REQUIRED_SIGNALS = 2

def get_worker_identity_status(worker_id: int) -> bool:
    """
    Check if the worker's recovery identity is verified.
    Identity is cryptographic, not a liveness signal. This checks:
    - The worker exists in the workers table.
    - The worker's SSH host key fingerprint is pinned.

    Heartbeat freshness is deliberately not required here: a worker that has
    been down long enough to need recovery will necessarily have an old
    heartbeat. Repair still requires independent fresh failure evidence and
    the recovery SSH connection itself is verified against the pinned key.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, status, ssh_host_key_fingerprint, last_heartbeat_at
        FROM workers WHERE id = ?
        """,
        (worker_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        logger.warning(f"Worker {worker_id} not found")
        return False

    # Check identity: must have a pinned host key
    if not row[2]:
        logger.warning(f"Worker {worker_id} has no pinned host key")
        return False

    return True

def get_health_signals(worker_id: int, service_name: str) -> List[Dict[str, Any]]:
    """
    Collect health signals for a given worker and service.
    Returns a list of signal dicts: {"type": str, "status": bool, "details": str}
    """
    signals = []
    conn = get_db_connection()
    cursor = conn.cursor()

    # Signal 1: Last health check result from the events table
    cursor.execute(
        """
        SELECT type, severity, details, timestamp
        FROM events
        WHERE worker_id = ? AND (type = 'health_check' OR type LIKE 'health_check.%')  -- M2 fix: also match exact 'health_check'
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        (worker_id,)
    )
    row = cursor.fetchone()
    if row:
        is_ok = row[1] == 'ok'  # severity 'ok' means healthy
        signals.append({
            "type": "health_check",
            "status": is_ok,
            "details": f"Last health check: {row[0]} (severity {row[1]})",
            "timestamp": row[3]
        })

    # If the machine answers a separate SSH probe while its authenticated API
    # is down, that independently confirms a Lattice-service outage.
    cursor.execute(
        """
        SELECT message, timestamp FROM events
        WHERE worker_id = ? AND type = 'ssh_probe.worker_api_down'
        ORDER BY timestamp DESC LIMIT 1
        """,
        (worker_id,),
    )
    ssh_row = cursor.fetchone()
    if ssh_row:
        try:
            probed_at = datetime.fromisoformat(ssh_row[1])
            if probed_at.tzinfo is None:
                probed_at = probed_at.replace(tzinfo=timezone.utc)
            fresh = datetime.now(timezone.utc) - probed_at <= timedelta(seconds=60)
        except (TypeError, ValueError):
            fresh = False
        if fresh:
            signals.append({
                "type": "ssh_probe",
                "status": False,
                "details": ssh_row[0],
                "timestamp": ssh_row[1],
            })

    # Another possible independent signal: a fresh worker service report.
    cursor.execute(
        """
        SELECT name, status, last_reported_at FROM services
        WHERE worker_id = ? AND name = ?
        """,
        (worker_id, service_name)
    )
    row = cursor.fetchone()
    if row and row[2]:
        try:
            reported_at = datetime.fromisoformat(row[2])
            if reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            fresh = datetime.now(timezone.utc) - reported_at <= timedelta(seconds=60)
        except (TypeError, ValueError):
            fresh = False
        if fresh:
            is_ok = is_service_healthy(row[1])
            signals.append({
                "type": "service_status",
                "status": is_ok,
                "details": f"Fresh worker report for {row[0]}: {row[1]}",
                "timestamp": row[2],
            })
        else:
            logger.warning("Ignoring stale service report for worker %s service %s", worker_id, service_name)

    conn.close()
    return signals

def should_heal(worker_id: int, service_name: str) -> bool:
    """
    Determine if auto-heal should act based on the 2‑signal requirement
    and identity confidence check.
    Returns True if all conditions pass.
    """
    # 1. Identity check
    if not get_worker_identity_status(worker_id):
        logger.info(f"Worker {worker_id} identity not verified, skipping heal")
        return False

    # 2. Collect signals
    signals = get_health_signals(worker_id, service_name)

    # Count independent signals indicating failure
    failure_signals = [s for s in signals if s["status"] is False]
    if len(failure_signals) >= REQUIRED_SIGNALS:
        logger.info(f"Worker {worker_id} has {len(failure_signals)} independent failure signals, healing allowed")
        return True
    else:
        logger.info(f"Worker {worker_id} only has {len(failure_signals)} failure signals (need {REQUIRED_SIGNALS}), skipping heal")
        return False

def get_required_signals_count() -> int:
    """Return the required number of independent signals for healing."""
    return REQUIRED_SIGNALS
worker_identity_verified = get_worker_identity_status
get_independent_signals = should_heal
