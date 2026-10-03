"""Pure recovery proofs for backup incidents.

These checks never run retention, prune snapshots, or start a backup.
They only decide whether persisted evidence proves that an older failure
condition has subsequently recovered.
"""
from __future__ import annotations

from datetime import datetime, timezone

from lattice.core.db import get_db_connection

_CONNECTIVITY_MARKERS = (
    "no route to host",
    "network is unreachable",
    "connection refused",
    "connection timed out",
    "name or service not known",
    "temporary failure in name resolution",
    "error receiving version packet",
)


def _connectivity_failure(error: str) -> bool:
    if any(marker in error for marker in _CONNECTIVITY_MARKERS):
        return True
    return "unexpected eof" in error and any(
        marker in error for marker in ("ssh", "sftp", "version packet")
    )


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def maintenance_failure_recovered(job_id: int) -> tuple[bool, str]:
    """Return whether a stored maintenance failure is proven obsolete."""
    conn = get_db_connection()
    try:
        state = conn.execute(
            """SELECT last_result,last_error,updated_at
               FROM backup_maintenance_state WHERE job_id=?""",
            (int(job_id),),
        ).fetchone()
        if state is None or state["last_result"] != "failed":
            return True, "maintenance state is not failed"
        error = str(state["last_error"] or "").lower()
        failed_at = _parse(state["updated_at"])
        if not error or not _connectivity_failure(error):
            return False, "maintenance failure requires a successful maintenance verification"
        success = conn.execute(
            """SELECT finished_at FROM backup_runs
               WHERE job_id=? AND result='successful'
               ORDER BY id DESC LIMIT 1""",
            (int(job_id),),
        ).fetchone()
        if success is None:
            return False, "no successful backup followed the maintenance failure"
        succeeded_at = _parse(success["finished_at"])
        if failed_at is None or succeeded_at is None or succeeded_at <= failed_at:
            return False, "no newer successful backup proves transport recovery"
        observation = conn.execute(
            """SELECT state,last_result,failure_streak,credential_missing
               FROM backup_job_observations WHERE job_id=?""",
            (int(job_id),),
        ).fetchone()
        if observation is None:
            return False, "current backup observation is unavailable"
        if str(observation["state"]) not in {"healthy", "running"}:
            return False, f"backup state is {observation['state']}"
        if int(observation["failure_streak"] or 0) != 0:
            return False, "backup still has a failure streak"
        if bool(observation["credential_missing"]):
            return False, "backup credential is still unavailable"
        return True, "newer successful backup proves the prior transport failure recovered"
    finally:
        conn.close()


def all_local_maintenance_failures_recovered(node_id: str) -> tuple[bool, list[str]]:
    """Evaluate every enabled backup job sourced by one node."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bj.id FROM backup_jobs bj
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.source_node_id=? AND bj.enabled=1 AND bt.enabled=1""",
            (node_id,),
        ).fetchall()
    finally:
        conn.close()
    reasons: list[str] = []
    for row in rows:
        ok, reason = maintenance_failure_recovered(int(row["id"]))
        if not ok:
            reasons.append(f"backup job {int(row['id'])}: {reason}")
    return not reasons, reasons


def backup_alert_recovery(event_type: str, details: dict) -> tuple[bool | None, str]:
    """Return True/False/None for recovered/active/unknown backup incidents."""
    job_id = details.get("job_id")
    target_id = details.get("target_id")
    if event_type == "backup.verification_failed":
        if not isinstance(job_id, int):
            return None, "backup verification alert has no valid job ID"
        return maintenance_failure_recovered(job_id)

    conn = get_db_connection()
    try:
        if isinstance(job_id, int):
            job = conn.execute(
                """SELECT bjo.*, bj.created_at
                   FROM backup_jobs bj
                   LEFT JOIN backup_job_observations bjo ON bjo.job_id=bj.id
                   WHERE bj.id=?""",
                (job_id,),
            ).fetchone()
        else:
            job = None
        if isinstance(target_id, int):
            target = conn.execute(
                "SELECT * FROM backup_target_observations WHERE target_id=?",
                (target_id,),
            ).fetchone()
        else:
            target = None
        if event_type in {"backup.overdue", "backup.severely_overdue"}:
            if job is None or not job["last_success_at"]:
                return False, "backup still has no successful completion"
            last_success = _parse(job["last_success_at"])
            if last_success is None:
                return None, "backup success timestamp is invalid"
            age = datetime.now(timezone.utc) - last_success
            limit = 48 if event_type == "backup.severely_overdue" else 24
            return age.total_seconds() < limit * 3600, "backup success age rechecked"
        if event_type == "backup.credential_missing":
            if job is None:
                return None, "backup job observation is unavailable"
            return not bool(job["credential_missing"]), "backup credential state rechecked"
        if event_type == "backup.repeated_failure":
            if job is None:
                return None, "backup job observation is unavailable"
            return int(job["failure_streak"] or 0) < 3, "backup failure streak rechecked"
        if event_type == "backup.status_stale":
            if job is None or not job["last_reported_at"]:
                return False, "backup status is still unavailable"
            reported = _parse(job["last_reported_at"])
            if reported is None:
                return None, "backup observation timestamp is invalid"
            age = datetime.now(timezone.utc) - reported
            return age.total_seconds() <= 60, "backup observation freshness rechecked"
        if event_type == "backup.target_status_unknown":
            if target is None:
                return False, "backup target observation is unavailable"
            return target["health"] == "healthy", "backup target health rechecked"
        if event_type == "backup.target_missing":
            if target is None:
                return False, "backup target observation is unavailable"
            return bool(target["present"]) and target["health"] == "healthy", "backup target presence rechecked"
        if event_type == "backup.low_space":
            if target is None or not target["total_bytes"]:
                return False, "backup target capacity is unavailable"
            free_pct = (int(target["free_bytes"] or 0) / int(target["total_bytes"])) * 100.0
            from lattice.core.config import load_config
            reserve = float(load_config().backup.free_space_reserve_percent)
            return free_pct >= reserve, "backup target free-space reserve rechecked"
        return None, f"no verifier is registered for {event_type}"
    finally:
        conn.close()
