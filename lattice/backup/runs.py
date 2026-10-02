"""Durable backup run state and operator-friendly health summaries."""
from __future__ import annotations

from datetime import datetime, timezone

from lattice.core.db import get_db_connection


class BackupRunError(RuntimeError):
    pass


def _job(job_id: int):
    if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
        raise BackupRunError("Backup job ID is invalid")
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bj.*, fn.hostname AS source_hostname, bt.friendly_name AS target_name
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.id=?""",
            (job_id,),
        ).fetchone()
        return dict(row) if row is not None else None
    finally:
        conn.close()


def begin_run(job_id: int, *, recover_abandoned: bool = False) -> dict:
    job = _job(job_id)
    if job is None:
        raise BackupRunError("Backup job was not found")
    if job["paused"]:
        raise BackupRunError(f"Backup is paused: {job['pause_reason']}")
    conn = get_db_connection()
    try:
        active = conn.execute(
            "SELECT id FROM backup_runs WHERE job_id=? AND result='running' LIMIT 1",
            (job_id,),
        ).fetchone()
        if active is not None:
            if not recover_abandoned:
                raise BackupRunError("A backup is already running for this computer and target")
            # Callers request recovery only while holding the exclusive per-job
            # repository lock. No real operation can still own the repository,
            # so any durable running row is abandoned process/reboot state.
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """UPDATE backup_runs
                   SET finished_at=?, result='interrupted',
                       error_code='process_interrupted',
                       error_message='Previous backup process ended before recording completion'
                   WHERE job_id=? AND result='running'""",
                (now, job_id),
            )
        cursor = conn.execute(
            "INSERT INTO backup_runs(job_id,started_at,result) VALUES(?,?, 'running')",
            (job_id, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return dict(conn.execute("SELECT * FROM backup_runs WHERE id=?", (cursor.lastrowid,)).fetchone())
    finally:
        conn.close()


def finish_run(run_id: int, *, result: str, snapshot_id: str | None = None, bytes_added: int | None = None, error_code: str | None = None, error_message: str | None = None) -> dict:
    if result not in {"successful", "interrupted", "failed", "cancelled"}:
        raise BackupRunError("Backup run result is invalid")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
        raise BackupRunError("Backup run ID is invalid")
    if bytes_added is not None and (isinstance(bytes_added, bool) or bytes_added < 0):
        raise BackupRunError("Backup byte count is invalid")
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            """UPDATE backup_runs SET finished_at=?, result=?, snapshot_id=?, bytes_added=?,
                      error_code=?, error_message=?
               WHERE id=? AND result='running'""",
            (datetime.now(timezone.utc).isoformat(), result, snapshot_id, bytes_added, error_code, error_message, run_id),
        )
        if cursor.rowcount != 1:
            raise BackupRunError("Backup run was not found or is already finished")
        conn.commit()
        return dict(conn.execute("SELECT * FROM backup_runs WHERE id=?", (run_id,)).fetchone())
    finally:
        conn.close()

def job_summary(job_id: int) -> dict:
    job = _job(job_id)
    if job is None:
        raise BackupRunError("Backup job was not found")
    conn = get_db_connection()
    try:
        latest = conn.execute(
            "SELECT * FROM backup_runs WHERE job_id=? ORDER BY id DESC LIMIT 1", (job_id,)
        ).fetchone()
        success = conn.execute(
            "SELECT * FROM backup_runs WHERE job_id=? AND result='successful' ORDER BY id DESC LIMIT 1", (job_id,)
        ).fetchone()
    finally:
        conn.close()
    if job["paused"]:
        state, detail = "paused", job["pause_reason"]
    elif latest is not None and latest["result"] == "running":
        state, detail = "running", "Backup is running now"
    elif success is None:
        state, detail = "never_backed_up", "No successful backup yet"
    elif latest is not None and latest["result"] in {"failed", "interrupted"}:
        state, detail = "pending", "Last attempt did not complete; Lattice will retry"
    else:
        state, detail = "healthy", "Latest backup completed successfully"
    return {
        "job_id": job_id, "source_hostname": job["source_hostname"], "target_name": job["target_name"],
        "state": state, "detail": detail,
        "last_success_at": success["finished_at"] if success is not None else None,
        "last_result": latest["result"] if latest is not None else None,
    }
