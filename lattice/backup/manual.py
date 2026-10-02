"""Narrow manual backup request queue and root-side execution."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid

from lattice.backup.runner import BackupExecutionError, _load_job, run_local_job, run_remote_job
from lattice.file_access.identity import load_node_identity

DEFAULT_REQUEST_PATH = Path("/var/lib/lattice/backup-run-request.json")
DEFAULT_RESULT_PATH = Path("/var/lib/lattice/backup-run-result.json")


class ManualBackupError(RuntimeError):
    pass


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ManualBackupError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise ManualBackupError(f"{label} must be UUIDv4")
    return str(parsed)


def _request_path() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_RUN_REQUEST_PATH", str(DEFAULT_REQUEST_PATH)))


def _result_path() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_RUN_RESULT_PATH", str(DEFAULT_RESULT_PATH)))


def _atomic_write(path: Path, payload: dict, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), mode)
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_create(path: Path, payload: dict, *, mode: int = 0o600) -> bool:
    """Publish a complete request only if no request already exists."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), mode)
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            return False
        os.chmod(path, mode)
        return True
    finally:
        temporary.unlink(missing_ok=True)


def _safe_read(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ManualBackupError("Manual backup request path is unsafe")
        if metadata.st_mode & 0o022 or metadata.st_size > 16384:
            raise ManualBackupError("Manual backup request permissions or size are unsafe")
        raw = os.read(descriptor, 16385)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManualBackupError("Manual backup request is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ManualBackupError("Manual backup request must be an object")
    return payload


def queue_manual_backup(
    job_uuid: str,
    *,
    full_speed: bool = False,
    allow_large_first_backup: bool = False,
) -> bool:
    """Queue exactly one local source-owned job for immediate root execution."""
    job_uuid = _uuid4(job_uuid, "Backup job ID")
    if not isinstance(full_speed, bool):
        raise ManualBackupError("Full Speed override must be boolean")
    if not isinstance(allow_large_first_backup, bool):
        raise ManualBackupError("Large Backup confirmation must be boolean")
    identity = load_node_identity()
    if identity is None:
        raise ManualBackupError("Local Lattice node identity is unavailable")
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bj.id,bj.paused,bj.enabled,bj.source_node_id,bt.enabled AS target_enabled
               FROM backup_jobs bj JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.job_uuid=?""",
            (job_uuid,),
        ).fetchone()
    finally:
        conn.close()
    if row is None or not bool(row["enabled"]) or not bool(row["target_enabled"]):
        raise ManualBackupError("Backup job is unavailable")
    if row["source_node_id"] != identity.node_id:
        raise ManualBackupError("Backup job belongs to a different source computer")
    if bool(row["paused"]):
        raise ManualBackupError("Paused backup must be resumed before running it now")

    path = _request_path()
    payload = {
        "schema_version": 1,
        "job_uuid": job_uuid,
        "full_speed": full_speed,
        "allow_large_first_backup": allow_large_first_backup,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    if _atomic_create(path, payload):
        return True
    existing = _safe_read(path)
    if (
        existing.get("job_uuid") == job_uuid
        and bool(existing.get("full_speed", False)) == full_speed
        and bool(existing.get("allow_large_first_backup", False)) == allow_large_first_backup
    ):
        return False
    raise ManualBackupError("Another manual backup request is already pending")


def execute_manual_request() -> dict:
    """Root entry point: consume, revalidate, and execute one manual request."""
    if os.geteuid() != 0:
        raise ManualBackupError("Manual backup execution must run as root")
    path = _request_path()
    output: dict | None = None
    job_uuid: str | None = None
    try:
        payload = _safe_read(path)
        if payload.get("schema_version") != 1:
            raise ManualBackupError("Manual backup request schema is invalid")
        job_uuid = _uuid4(payload.get("job_uuid"), "Backup job ID")
        full_speed = payload.get("full_speed", False)
        if not isinstance(full_speed, bool):
            raise ManualBackupError("Manual backup Full Speed flag is invalid")
        allow_large_first_backup = payload.get("allow_large_first_backup", False)
        if not isinstance(allow_large_first_backup, bool):
            raise ManualBackupError("Manual backup Large Backup confirmation is invalid")
        identity = load_node_identity()
        if identity is None:
            raise ManualBackupError("Local Lattice node identity is unavailable")

        from lattice.core.db import get_db_connection
        conn = get_db_connection()
        try:
            row = conn.execute(
                """SELECT bj.id,bj.enabled,bj.paused,bj.source_node_id,bt.host_node_id,bt.enabled AS target_enabled
                   FROM backup_jobs bj JOIN backup_targets bt ON bt.id=bj.target_id
                   WHERE bj.job_uuid=?""",
                (job_uuid,),
            ).fetchone()
        finally:
            conn.close()
        if row is None or not bool(row["enabled"]) or not bool(row["target_enabled"]):
            raise ManualBackupError("Backup job is unavailable")
        if row["source_node_id"] != identity.node_id:
            raise ManualBackupError("Backup job belongs to a different source computer")
        if bool(row["paused"]):
            raise ManualBackupError("Paused backup cannot be run manually")

        if row["host_node_id"] == identity.node_id:
            result = run_local_job(
                int(row["id"]), local_node_id=identity.node_id,
                allow_large_first_backup=allow_large_first_backup,
            )
        else:
            result = run_remote_job(
                int(row["id"]), local_node_id=identity.node_id,
                full_speed=full_speed, allow_large_first_backup=allow_large_first_backup,
            )
        output = {
            "status": "successful", "job_uuid": job_uuid,
            "snapshot_id": result.get("snapshot_id"),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }
        return output
    except Exception as exc:
        output = {
            "status": "failed", "job_uuid": job_uuid,
            "error": str(exc)[:1000],
            "finished_at": datetime.now(timezone.utc).isoformat(),
        }
        if isinstance(exc, ManualBackupError):
            raise
        if isinstance(exc, BackupExecutionError):
            raise ManualBackupError(str(exc)) from exc
        raise
    finally:
        if output is not None:
            _atomic_write(_result_path(), output)
        path.unlink(missing_ok=True)

def main() -> None:
    result = execute_manual_request()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
