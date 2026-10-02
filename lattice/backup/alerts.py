"""Master-side backup incident evaluation using the existing Lattice alert system."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from lattice.backup.observations import (
    local_backup_observations,
    local_backup_target_observations,
)
from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.core.events import create_alert, log_event, resolve_alert
from lattice.file_access.identity import load_node_identity


class BackupAlertError(RuntimeError):
    pass


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


def _title(kind: str, source: str, target: str) -> str:
    return f"{kind}: {source} → {target}"[:240]


def _active_alert_id(worker_id: int | None, title: str) -> int | None:
    conn = get_db_connection()
    try:
        if worker_id is None:
            row = conn.execute(
                "SELECT id FROM alerts WHERE worker_id IS NULL AND title=? AND resolved_at IS NULL ORDER BY id LIMIT 1",
                (title,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT id FROM alerts WHERE worker_id=? AND title=? AND resolved_at IS NULL ORDER BY id LIMIT 1",
                (worker_id, title),
            ).fetchone()
        return int(row["id"]) if row is not None else None
    finally:
        conn.close()


def _set_incident(
    *,
    active: bool,
    worker_id: int | None,
    title: str,
    severity: str,
    message: str,
    event_type: str,
    details: dict,
) -> None:
    alert_id = _active_alert_id(worker_id, title)
    if active:
        if alert_id is not None:
            return
        event_id = log_event(worker_id, event_type, severity, message, details)
        create_alert(worker_id, severity, title, message, event_id)
        return
    if alert_id is None:
        return
    event_id = log_event(
        worker_id,
        "backup.recovered",
        "info",
        f"Resolved: {message}",
        details,
    )
    resolve_alert(alert_id, event_id)


def refresh_local_master_observations(now_iso: str) -> None:
    """Mirror the master's own source/target state into the same observation tables."""
    identity = load_node_identity()
    if identity is None:
        return
    conn = get_db_connection()
    try:
        local = conn.execute(
            "SELECT role FROM fleet_nodes WHERE node_id=? AND membership_state='active'",
            (identity.node_id,),
        ).fetchone()
        if local is None or local["role"] != "master":
            return

        for observation in local_backup_observations():
            row = conn.execute(
                """SELECT bj.id FROM backup_jobs bj
                   JOIN backup_targets bt ON bt.id=bj.target_id
                   WHERE bj.job_uuid=? AND bj.source_node_id=? AND bt.target_uuid=?""",
                (
                    observation["job_uuid"], identity.node_id,
                    observation["target_uuid"],
                ),
            ).fetchone()
            if row is None:
                continue
            job_id = int(row["id"])
            existing = conn.execute(
                "SELECT state, problem_since FROM backup_job_observations WHERE job_id=?",
                (job_id,),
            ).fetchone()
            healthy = observation["state"] in {"healthy", "running", "paused"}
            if healthy:
                problem_since = None
            elif existing is None or existing["state"] in {"healthy", "running", "paused"} or not existing["problem_since"]:
                problem_since = now_iso
            else:
                problem_since = existing["problem_since"]
            conn.execute(
                """INSERT INTO backup_job_observations(
                       job_id,observer_node_id,state,last_success_at,last_result,
                       failure_streak,problem_since,maintenance_result,maintenance_error,
                       credential_missing,last_deep_verification_at,last_reported_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(job_id) DO UPDATE SET
                     observer_node_id=excluded.observer_node_id,
                     state=excluded.state,
                     last_success_at=excluded.last_success_at,
                     last_result=excluded.last_result,
                     failure_streak=excluded.failure_streak,
                     problem_since=excluded.problem_since,
                     maintenance_result=excluded.maintenance_result,
                     maintenance_error=excluded.maintenance_error,
                     credential_missing=excluded.credential_missing,
                     last_deep_verification_at=excluded.last_deep_verification_at,
                     last_reported_at=excluded.last_reported_at""",
                (
                    job_id, identity.node_id, observation["state"],
                    observation["last_success_at"], observation["last_result"],
                    observation["failure_streak"], problem_since,
                    observation["maintenance_result"], observation["maintenance_error"],
                    1 if observation["credential_missing"] else 0,
                    observation["last_deep_verification_at"], now_iso,
                ),
            )

        for observation in local_backup_target_observations():
            row = conn.execute(
                "SELECT id FROM backup_targets WHERE target_uuid=? AND host_node_id=?",
                (observation["target_uuid"], identity.node_id),
            ).fetchone()
            if row is None:
                continue
            target_id = int(row["id"])
            existing = conn.execute(
                "SELECT present, problem_since FROM backup_target_observations WHERE target_id=?",
                (target_id,),
            ).fetchone()
            if observation["present"]:
                problem_since = None
            elif existing is None or bool(existing["present"]) or not existing["problem_since"]:
                problem_since = now_iso
            else:
                problem_since = existing["problem_since"]
            conn.execute(
                """INSERT INTO backup_target_observations(
                       target_id,observer_node_id,present,problem_since,filesystem_uuid,
                       mountpoint,total_bytes,free_bytes,health,last_reported_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(target_id) DO UPDATE SET
                     observer_node_id=excluded.observer_node_id,
                     present=excluded.present,
                     problem_since=excluded.problem_since,
                     filesystem_uuid=excluded.filesystem_uuid,
                     mountpoint=excluded.mountpoint,
                     total_bytes=excluded.total_bytes,
                     free_bytes=excluded.free_bytes,
                     health=excluded.health,
                     last_reported_at=excluded.last_reported_at""",
                (
                    target_id, identity.node_id, 1 if observation["present"] else 0,
                    problem_since, observation["filesystem_uuid"],
                    observation["mountpoint"], observation["total_bytes"],
                    observation["free_bytes"], observation["health"], now_iso,
                ),
            )
        conn.commit()
    finally:
        conn.close()


def _refresh_local_master_observations(now_iso: str) -> None:
    """Backward-compatible internal hook used by alert evaluation/tests."""
    refresh_local_master_observations(now_iso)


def sync_backup_alerts(*, now: datetime | None = None) -> None:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    now_iso = now.isoformat()
    _refresh_local_master_observations(now_iso)
    config = load_config().backup
    persistent = timedelta(seconds=config.persistent_alert_seconds)
    reserve = float(config.free_space_reserve_percent)

    conn = get_db_connection()
    try:
        jobs = conn.execute(
            """SELECT bj.id,bj.created_at,bj.paused,fn.hostname AS source_hostname,
                      fn.worker_id,bt.friendly_name AS target_name,
                      bjo.state,bjo.last_success_at,bjo.last_result,bjo.failure_streak,
                      bjo.problem_since,bjo.maintenance_result,bjo.maintenance_error,
                      bjo.credential_missing,bjo.last_reported_at
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               LEFT JOIN backup_job_observations bjo ON bjo.job_id=bj.id
               WHERE bj.enabled=1 AND bt.enabled=1 AND fn.membership_state='active'
               ORDER BY bj.id"""
        ).fetchall()
        targets = conn.execute(
            """SELECT bt.id,bt.friendly_name,fn.hostname AS host_hostname,fn.worker_id,
                      bto.present,bto.problem_since,bto.total_bytes,bto.free_bytes,bto.health,
                      bto.last_reported_at
               FROM backup_targets bt
               JOIN fleet_nodes fn ON fn.node_id=bt.host_node_id
               LEFT JOIN backup_target_observations bto ON bto.target_id=bt.id
               WHERE bt.enabled=1 AND fn.membership_state='active'
               ORDER BY bt.id"""
        ).fetchall()
    finally:
        conn.close()

    for row in jobs:
        source = str(row["source_hostname"])
        target = str(row["target_name"])
        worker_id = row["worker_id"]
        details = {"job_id": int(row["id"]), "source": source, "target": target}
        paused = bool(row["paused"])
        baseline = _parse(row["last_success_at"]) or _parse(row["created_at"])
        age = now - baseline if baseline is not None else timedelta.max
        severe = not paused and age >= timedelta(hours=48)
        overdue = not paused and age >= timedelta(hours=24) and not severe

        warning_title = _title("Backup overdue", source, target)
        critical_title = _title("Backup severely overdue", source, target)
        _set_incident(
            active=overdue,
            worker_id=worker_id,
            title=warning_title,
            severity="warning",
            message=f"{source} has not completed a successful backup to {target} in over 24 hours.",
            event_type="backup.overdue",
            details=details,
        )
        _set_incident(
            active=severe,
            worker_id=worker_id,
            title=critical_title,
            severity="critical",
            message=f"{source} has not completed a successful backup to {target} in over 48 hours.",
            event_type="backup.severely_overdue",
            details=details,
        )

        credential_missing = not paused and bool(row["credential_missing"])
        _set_incident(
            active=credential_missing,
            worker_id=worker_id,
            title=_title("Backup credential missing", source, target),
            severity="critical",
            message=(
                f"{source} cannot access the encrypted backup credential for {target}. "
                "Lattice will not generate a replacement credential for an established repository."
            ),
            event_type="backup.credential_missing",
            details=details,
        )

        repeated = not paused and int(row["failure_streak"] or 0) >= 3
        _set_incident(
            active=repeated,
            worker_id=worker_id,
            title=_title("Backup repeatedly failing", source, target),
            severity="warning",
            message=f"{source} has failed to back up to {target} at least three consecutive times.",
            event_type="backup.repeated_failure",
            details={**details, "failure_streak": int(row["failure_streak"] or 0)},
        )

        reported_at = _parse(row["last_reported_at"])
        observation_stale = (
            not paused
            and worker_id is not None
            and (reported_at is None or now - reported_at > timedelta(seconds=60))
        )
        _set_incident(
            active=observation_stale,
            worker_id=worker_id,
            title=_title("Backup status stale", source, target),
            severity="warning",
            message=f"{source} has not reported current backup status for {target}.",
            event_type="backup.status_stale",
            details=details,
        )

        maintenance_failed = not paused and row["maintenance_result"] == "failed"
        maintenance_message = (
            str(row["maintenance_error"] or "Repository maintenance or verification failed")[:500]
        )
        _set_incident(
            active=maintenance_failed,
            worker_id=worker_id,
            title=_title("Backup maintenance failed", source, target),
            severity="critical",
            message=f"Backup maintenance/verification failed for {source} → {target}: {maintenance_message}",
            event_type="backup.verification_failed",
            details=details,
        )

    for row in targets:
        target = str(row["friendly_name"])
        host = str(row["host_hostname"])
        worker_id = row["worker_id"]
        problem_since = _parse(row["problem_since"])
        missing = (
            row["present"] is not None
            and not bool(row["present"])
            and problem_since is not None
            and now - problem_since >= persistent
        )
        details = {"target_id": int(row["id"]), "target": target, "host": host}
        missing = missing and row["health"] == "offline"
        reported_at = _parse(row["last_reported_at"])
        status_unknown = (
            row["health"] == "unknown"
            or (worker_id is not None and (reported_at is None or now - reported_at > timedelta(seconds=60)))
        )
        _set_incident(
            active=status_unknown,
            worker_id=worker_id,
            title=f"Backup target status unknown: {target}"[:240],
            severity="warning",
            message=f"Lattice cannot currently verify backup target {target} on {host}.",
            event_type="backup.target_status_unknown",
            details=details,
        )
        _set_incident(
            active=missing,
            worker_id=worker_id,
            title=f"Backup target missing: {target}"[:240],
            severity="warning",
            message=f"{target} on {host} has remained unavailable long enough to affect backup protection.",
            event_type="backup.target_missing",
            details=details,
        )

        total = row["total_bytes"]
        free = row["free_bytes"]
        free_percent = None
        if total is not None and free is not None and int(total) > 0:
            free_percent = (int(free) / int(total)) * 100.0
        low_space = bool(row["present"]) and free_percent is not None and free_percent < reserve
        _set_incident(
            active=low_space,
            worker_id=worker_id,
            title=f"Backup target low space: {target}"[:240],
            severity="warning" if free_percent is None or free_percent >= 10 else "critical",
            message=(
                f"{target} on {host} has {free_percent:.1f}% free; Lattice reserves {reserve:.0f}%."
                if free_percent is not None else f"{target} on {host} is below its free-space reserve."
            ),
            event_type="backup.low_space",
            details={**details, "free_percent": free_percent, "reserve_percent": reserve},
        )


def main() -> None:
    sync_backup_alerts()


if __name__ == '__main__':
    main()
