"""Bounded fleet reporting for source-owned backup health."""
from __future__ import annotations

from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

_ALLOWED_STATES = {
    "healthy",
    "running",
    "pending",
    "paused",
    "never_backed_up",
}
_ALLOWED_RESULTS = {None, "running", "successful", "interrupted", "failed", "cancelled"}
_ALLOWED_MAINTENANCE_RESULTS = {None, "healthy", "degraded", "failed"}


class BackupObservationError(ValueError):
    pass


def _state(paused: bool, latest_result: str | None, last_success_at: str | None) -> str:
    if paused:
        return "paused"
    if latest_result == "running":
        return "running"
    if last_success_at is None:
        return "never_backed_up"
    if latest_result in {"failed", "interrupted"}:
        return "pending"
    return "healthy"


def local_backup_observations() -> list[dict]:
    identity = load_node_identity()
    if identity is None:
        return []
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bj.job_uuid, bt.target_uuid, bj.paused,
                      (SELECT br.result FROM backup_runs br
                       WHERE br.job_id=bj.id ORDER BY br.id DESC LIMIT 1) AS last_result,
                      (SELECT br.error_message FROM backup_runs br
                       WHERE br.job_id=bj.id ORDER BY br.id DESC LIMIT 1) AS last_error_message,
                      (SELECT br.finished_at FROM backup_runs br
                       WHERE br.job_id=bj.id AND br.result='successful'
                       ORDER BY br.id DESC LIMIT 1) AS last_success_at,
                      (SELECT COUNT(*) FROM backup_runs br
                       WHERE br.job_id=bj.id
                         AND br.result IN ('failed','interrupted')
                         AND br.id > COALESCE((SELECT MAX(ok.id) FROM backup_runs ok
                                               WHERE ok.job_id=bj.id AND ok.result='successful'), 0)
                      ) AS failure_streak,
                      bms.last_result AS maintenance_result,
                      bms.last_error AS maintenance_error,
                      bms.last_deep_verification_at
               FROM backup_jobs bj
               JOIN backup_targets bt ON bt.id=bj.target_id
               LEFT JOIN backup_maintenance_state bms ON bms.job_id=bj.id
               WHERE bj.source_node_id=? AND bj.enabled=1 AND bt.enabled=1
               ORDER BY bj.id LIMIT 32""",
            (identity.node_id,),
        ).fetchall()
        return [
            {
                "observer_node_id": identity.node_id,
                "job_uuid": str(row["job_uuid"]),
                "target_uuid": str(row["target_uuid"]),
                "state": _state(bool(row["paused"]), row["last_result"], row["last_success_at"]),
                "last_result": row["last_result"],
                "last_success_at": row["last_success_at"],
                "failure_streak": int(row["failure_streak"] or 0),
                "credential_missing": (
                    "credential" in str(row["last_error_message"] or "").lower()
                    and "missing" in str(row["last_error_message"] or "").lower()
                ) or (
                    "credential" in str(row["maintenance_error"] or "").lower()
                    and (
                        "missing" in str(row["maintenance_error"] or "").lower()
                        or "unavailable" in str(row["maintenance_error"] or "").lower()
                    )
                ),
                "maintenance_result": row["maintenance_result"],
                "maintenance_error": row["maintenance_error"],
                "last_deep_verification_at": row["last_deep_verification_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def normalize_backup_observations(payload: object, observer_node_id: str) -> list[dict]:
    if payload is None:
        return []
    if not isinstance(payload, list) or len(payload) > 32:
        raise BackupObservationError("Backup observations must be a bounded list")
    result: list[dict] = []
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise BackupObservationError("Backup observation must be an object")
        if raw.get("observer_node_id") != observer_node_id:
            raise BackupObservationError("Backup observation has the wrong observer Node ID")
        job_uuid = raw.get("job_uuid")
        target_uuid = raw.get("target_uuid")
        state = raw.get("state")
        if not isinstance(job_uuid, str) or not job_uuid or len(job_uuid) > 64 or job_uuid in seen:
            raise BackupObservationError("Backup observation job is invalid or duplicated")
        if not isinstance(target_uuid, str) or not target_uuid or len(target_uuid) > 64:
            raise BackupObservationError("Backup observation target is invalid")
        if state not in _ALLOWED_STATES:
            raise BackupObservationError("Backup observation state is invalid")
        last_result = raw.get("last_result")
        if last_result not in _ALLOWED_RESULTS:
            raise BackupObservationError("Backup observation result is invalid")
        last_success_at = raw.get("last_success_at")
        if last_success_at is not None and (
            not isinstance(last_success_at, str) or len(last_success_at) > 80
        ):
            raise BackupObservationError("Backup observation timestamp is invalid")
        failure_streak = raw.get("failure_streak", 0)
        if (
            isinstance(failure_streak, bool)
            or not isinstance(failure_streak, int)
            or failure_streak < 0
            or failure_streak > 1000
        ):
            raise BackupObservationError("Backup failure streak is invalid")
        credential_missing = raw.get("credential_missing", False)
        if not isinstance(credential_missing, bool):
            raise BackupObservationError("Backup credential-missing state must be boolean")
        maintenance_result = raw.get("maintenance_result")
        if maintenance_result not in _ALLOWED_MAINTENANCE_RESULTS:
            raise BackupObservationError("Backup maintenance result is invalid")
        maintenance_error = raw.get("maintenance_error")
        if maintenance_error is not None and (
            not isinstance(maintenance_error, str) or len(maintenance_error) > 1000
        ):
            raise BackupObservationError("Backup maintenance error is invalid")
        last_deep_verification_at = raw.get("last_deep_verification_at")
        if last_deep_verification_at is not None and (
            not isinstance(last_deep_verification_at, str)
            or len(last_deep_verification_at) > 80
        ):
            raise BackupObservationError("Backup verification timestamp is invalid")
        seen.add(job_uuid)
        result.append({
            "observer_node_id": observer_node_id,
            "job_uuid": job_uuid,
            "target_uuid": target_uuid,
            "state": state,
            "last_result": last_result,
            "last_success_at": last_success_at,
            "failure_streak": failure_streak,
            "credential_missing": credential_missing,
            "maintenance_result": maintenance_result,
            "maintenance_error": maintenance_error,
            "last_deep_verification_at": last_deep_verification_at,
        })
    return result


def backup_service_status(observations: list[dict]) -> str | None:
    """Map configured backup protection into existing service health semantics."""
    if not observations:
        return None
    healthy_states = {"healthy", "running"}
    return "healthy" if all(item.get("state") in healthy_states for item in observations) else "unhealthy"


def local_backup_target_observations() -> list[dict]:
    """Report registered targets physically hosted by this node."""
    import os
    from pathlib import Path

    from lattice.backup.targets import BackupTargetError, inspect_uuid_mount

    identity = load_node_identity()
    if identity is None:
        return []
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT target_uuid, filesystem_uuid
               FROM backup_targets
               WHERE host_node_id=? AND enabled=1
               ORDER BY id LIMIT 32""",
            (identity.node_id,),
        ).fetchall()
    finally:
        conn.close()

    result: list[dict] = []
    for row in rows:
        target_uuid = str(row["target_uuid"])
        filesystem_uuid = str(row["filesystem_uuid"])
        present = False
        mountpoint = None
        total_bytes = free_bytes = None
        health = "offline"
        try:
            mount = inspect_uuid_mount(filesystem_uuid)
            mountpoint = str(mount.target)
            present = True
            health = "readonly" if "ro" in mount.options else "healthy"
            stats = os.statvfs(Path(mountpoint))
            total_bytes = stats.f_blocks * stats.f_frsize
            free_bytes = stats.f_bavail * stats.f_frsize
        except (BackupTargetError, OSError, ValueError):
            health = "unknown"
        result.append({
            "observer_node_id": identity.node_id,
            "target_uuid": target_uuid,
            "present": present,
            "filesystem_uuid": filesystem_uuid if present else None,
            "mountpoint": mountpoint,
            "total_bytes": total_bytes,
            "free_bytes": free_bytes,
            "health": health,
        })
    return result


def normalize_backup_target_observations(payload: object, observer_node_id: str) -> list[dict]:
    if payload is None:
        return []
    if not isinstance(payload, list) or len(payload) > 32:
        raise BackupObservationError("Backup target observations must be a bounded list")
    result: list[dict] = []
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise BackupObservationError("Backup target observation must be an object")
        if raw.get("observer_node_id") != observer_node_id:
            raise BackupObservationError("Backup target observation has the wrong observer Node ID")
        target_uuid = raw.get("target_uuid")
        if not isinstance(target_uuid, str) or not target_uuid or len(target_uuid) > 64 or target_uuid in seen:
            raise BackupObservationError("Backup target observation is invalid or duplicated")
        present = raw.get("present")
        if not isinstance(present, bool):
            raise BackupObservationError("Backup target presence must be boolean")
        health = raw.get("health")
        if health not in {"healthy", "offline", "readonly", "unknown"}:
            raise BackupObservationError("Backup target health is invalid")
        filesystem_uuid = raw.get("filesystem_uuid")
        mountpoint = raw.get("mountpoint")
        for value, label, limit in (
            (filesystem_uuid, "filesystem UUID", 128),
            (mountpoint, "mountpoint", 4096),
        ):
            if value is not None and (not isinstance(value, str) or len(value) > limit):
                raise BackupObservationError(f"Backup target {label} is invalid")
        if not present and (filesystem_uuid is not None or mountpoint is not None):
            raise BackupObservationError("Offline backup target must not claim a mounted filesystem")
        values: dict[str, int | None] = {}
        for key in ("total_bytes", "free_bytes"):
            value = raw.get(key)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
                raise BackupObservationError(f"Backup target {key} is invalid")
            values[key] = value
        if values["total_bytes"] is not None and values["free_bytes"] is not None:
            if values["free_bytes"] > values["total_bytes"]:
                raise BackupObservationError("Backup target free space exceeds total space")
        seen.add(target_uuid)
        result.append({
            "observer_node_id": observer_node_id,
            "target_uuid": target_uuid,
            "present": present,
            "filesystem_uuid": filesystem_uuid,
            "mountpoint": mountpoint,
            "total_bytes": values["total_bytes"],
            "free_bytes": values["free_bytes"],
            "health": health,
        })
    return result
