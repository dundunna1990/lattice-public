"""Nightly backup due-state calculation independent from systemd invocation."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from lattice.core.db import get_db_connection
from lattice.backup.config_state import runtime_policy

DEFAULT_SCHEDULE_HOUR = 2


def most_recent_schedule_boundary(
    now: datetime | None = None,
    *,
    schedule_hour: int = DEFAULT_SCHEDULE_HOUR,
) -> datetime:
    """Return the most recent local nightly boundary as a UTC timestamp."""
    if not 0 <= schedule_hour <= 23:
        raise ValueError("Backup schedule hour must be between 0 and 23")
    local_now = now or datetime.now().astimezone()
    if local_now.tzinfo is None:
        raise ValueError("Backup scheduler time must include a timezone")
    boundary = local_now.replace(
        hour=schedule_hour,
        minute=0,
        second=0,
        microsecond=0,
    )
    if local_now < boundary:
        boundary -= timedelta(days=1)
    return boundary.astimezone(timezone.utc)


def due_jobs(
    *,
    now: datetime | None = None,
    schedule_hour: int | None = None,
    source_node_id: str | None = None,
) -> list[dict]:
    """Return unpaused jobs without a success since the latest nightly boundary."""
    if schedule_hour is None:
        schedule_hour = int(runtime_policy()["schedule_hour"])
    cutoff = most_recent_schedule_boundary(
        now,
        schedule_hour=schedule_hour,
    ).isoformat()
    source_clause = "" if source_node_id is None else " AND bj.source_node_id=?"
    params: tuple[object, ...] = (
        (cutoff,)
        if source_node_id is None
        else (source_node_id, cutoff)
    )
    conn = get_db_connection()
    try:
        rows = conn.execute(
            f"""SELECT bj.id, bj.job_uuid, bj.source_node_id, bj.target_id, bj.source_path,
                      fn.hostname AS source_hostname, bt.friendly_name AS target_name,
                      CASE WHEN bj.source_node_id=bt.host_node_id
                           THEN 'local_storage' ELSE 'remote_storage' END AS target_type,
                      bt.host_node_id,
                      MAX(CASE WHEN br.result='successful' THEN br.finished_at END) AS last_success_at
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               LEFT JOIN backup_runs br ON br.job_id=bj.id
               WHERE bj.enabled=1 AND bj.paused=0 AND bt.enabled=1 AND fn.membership_state='active'{source_clause}
               GROUP BY bj.id
               HAVING last_success_at IS NULL OR last_success_at < ?
               ORDER BY fn.hostname COLLATE NOCASE, bt.friendly_name COLLATE NOCASE""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
