"""Validated backup target and job mutations."""
from __future__ import annotations

from pathlib import Path
import uuid

from lattice.core.db import get_db_connection


class BackupJobError(RuntimeError):
    pass


def _uuid4(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupJobError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupJobError(f"{label} must be UUIDv4")
    return str(parsed)


def _absolute(path: str, label: str) -> str:
    candidate = Path(path)
    if not candidate.is_absolute() or "\x00" in path or "\n" in path or "\r" in path:
        raise BackupJobError(f"{label} must be a safe absolute path")
    return str(candidate)


def register_target(*, friendly_name: str, host_node_id: str, filesystem_uuid: str, repository_root: str, target_type: str) -> dict:
    if target_type not in {"local_storage", "remote_storage"}:
        raise BackupJobError("Backup target type is invalid")
    if not isinstance(friendly_name, str) or not friendly_name.strip() or len(friendly_name.strip()) > 100:
        raise BackupJobError("Backup target name is invalid")
    if not isinstance(filesystem_uuid, str) or not filesystem_uuid.strip() or len(filesystem_uuid) > 128:
        raise BackupJobError("Backup filesystem UUID is invalid")
    host_node_id = _uuid4(host_node_id, "Backup target host node ID")
    repository_root = _absolute(repository_root, "Backup repository root")
    if Path(repository_root).name != "LatticeBackups":
        raise BackupJobError(
            "Backup V1 repository root must be the LatticeBackups folder on the selected drive"
        )
    target_uuid = str(uuid.uuid4())

    conn = get_db_connection()
    try:
        host = conn.execute("SELECT 1 FROM fleet_nodes WHERE node_id=? AND membership_state='active'", (host_node_id,)).fetchone()
        if host is None:
            raise BackupJobError("Backup target host is not an active Lattice computer")
        existing = conn.execute("SELECT id FROM backup_targets WHERE host_node_id=? AND filesystem_uuid=? AND enabled=1", (host_node_id, filesystem_uuid.strip())).fetchone()
        if existing is not None:
            raise BackupJobError("This filesystem is already registered as a backup target on that computer")
        relative_path = "LatticeBackups"
        cursor = conn.execute(
            """INSERT INTO backup_targets(
                   target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,
                   repository_root,repository_relative_path)
               VALUES(?,?,?,?,?,?,?)""",
            (
                target_uuid, friendly_name.strip(), host_node_id, target_type,
                filesystem_uuid.strip(), repository_root, relative_path,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM backup_targets WHERE id=?", (cursor.lastrowid,)).fetchone()
        return dict(row)
    finally:
        conn.close()


def create_job(*, source_node_id: str, target_id: int, source_path: str) -> dict:
    source_node_id = _uuid4(source_node_id, "Backup source node ID")
    source_path = _absolute(source_path, "Backup source path")
    if isinstance(target_id, bool) or not isinstance(target_id, int) or target_id < 1:
        raise BackupJobError("Backup target ID is invalid")

    conn = get_db_connection()
    try:
        source = conn.execute("SELECT main_user FROM fleet_nodes WHERE node_id=? AND membership_state='active'", (source_node_id,)).fetchone()
        if source is None:
            raise BackupJobError("Backup source is not an active Lattice computer")
        expected_home = f"/home/{source['main_user']}"
        if Path(source_path) != Path(expected_home):
            raise BackupJobError(f"Backup V1 source must be the computer's Home directory: {expected_home}")
        target = conn.execute("SELECT id FROM backup_targets WHERE id=? AND enabled=1", (target_id,)).fetchone()
        if target is None:
            raise BackupJobError("Backup target is unavailable or disabled")
        cursor = conn.execute(
            "INSERT INTO backup_jobs(job_uuid,source_node_id,target_id,source_path) VALUES(?,?,?,?)",
            (str(uuid.uuid4()), source_node_id, target_id, source_path),
        )
        conn.commit()
        return dict(conn.execute("SELECT * FROM backup_jobs WHERE id=?", (cursor.lastrowid,)).fetchone())
    except __import__('sqlite3').IntegrityError as exc:
        raise BackupJobError("This computer already has a backup job for that target") from exc
    finally:
        conn.close()


def set_job_paused(job_id: int, *, paused: bool, reason: str | None = None) -> dict:
    if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
        raise BackupJobError("Backup job ID is invalid")
    if paused:
        if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 200:
            raise BackupJobError("A clear pause reason is required")
        pause_reason = reason.strip()
    else:
        pause_reason = None

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE backup_jobs SET paused=?, pause_reason=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (1 if paused else 0, pause_reason, job_id),
        )
        if cursor.rowcount != 1:
            raise BackupJobError("Backup job was not found")
        conn.commit()
        return dict(conn.execute("SELECT * FROM backup_jobs WHERE id=?", (job_id,)).fetchone())
    finally:
        conn.close()


def register_discovered_target(
    candidate_id: str,
    *,
    friendly_name: str,
    maximum_candidate_age_seconds: int = 300,
) -> dict:
    """Register one currently visible storage candidate by opaque UI ID."""
    from datetime import datetime, timezone
    from lattice.backup.catalog import fleet_storage_candidates

    if not isinstance(candidate_id, str) or len(candidate_id) != 20:
        raise BackupJobError("Detected backup drive selection is invalid")
    if (
        isinstance(maximum_candidate_age_seconds, bool)
        or not isinstance(maximum_candidate_age_seconds, int)
        or maximum_candidate_age_seconds < 30
    ):
        raise BackupJobError("Backup drive freshness window is invalid")

    candidates = fleet_storage_candidates(include_sensitive=True)
    matches = [item for item in candidates if item["candidate_id"] == candidate_id]
    if len(matches) != 1:
        raise BackupJobError(
            "That detected drive is no longer available. Refresh storage and choose it again."
        )
    candidate = matches[0]
    if candidate["registered"]:
        raise BackupJobError(
            f"This drive is already registered as {candidate['registered_target_name']}"
        )

    # Remote candidates come from authenticated heartbeats. Refuse a stale
    # inventory rather than registering a disk that may have been unplugged.
    reported = candidate.get("last_reported_at")
    if reported is not None:
        try:
            seen_at = datetime.fromisoformat(str(reported))
        except ValueError as exc:
            raise BackupJobError("Detected backup drive timestamp is invalid") from exc
        if seen_at.tzinfo is None:
            seen_at = seen_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - seen_at.astimezone(timezone.utc)).total_seconds()
        if age < -60 or age > maximum_candidate_age_seconds:
            raise BackupJobError(
                "That detected drive is stale or offline. Wait for the computer to report it again."
            )

    repository_root = str(Path(candidate["mountpoint"]) / "LatticeBackups")
    # target_type remains a legacy storage-class field. Actual transport is
    # derived from source_node_id == host_node_id at execution time.
    return register_target(
        friendly_name=friendly_name,
        host_node_id=candidate["host_node_id"],
        filesystem_uuid=candidate["filesystem_uuid"],
        repository_root=repository_root,
        target_type="local_storage",
    )


def create_home_backup_job(*, source_node_id: str, target_id: int) -> dict:
    """Create the V1 Home backup without exposing a filesystem path in the UI."""
    source_node_id = _uuid4(source_node_id, "Backup source node ID")
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT main_user FROM fleet_nodes
               WHERE node_id=? AND membership_state='active'""",
            (source_node_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise BackupJobError("Backup source is not an active Lattice computer")
    return create_job(
        source_node_id=source_node_id,
        target_id=target_id,
        source_path=f"/home/{row['main_user']}",
    )
