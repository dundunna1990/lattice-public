"""Bounded read-only snapshot/query requests executed by the source node as root."""
from __future__ import annotations

from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import time
import uuid

from lattice.backup.credentials import BackupCredentialError, validate_password_file
from lattice.backup.remote import RemoteBackupError, connection_candidates
from lattice.backup.recovery import (
    BackupRecoveryError,
    DEFAULT_RECOVERY_STAGING_ROOT,
    full_home_recovery_preflight,
)
from lattice.backup.restic import ResticError, ResticRepository, ResticSFTPRepository
from lattice.backup.targets import BackupTargetError, resolve_repository_root
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

DEFAULT_REQUEST_PATH = Path("/var/lib/lattice/backup-query-request.json")
DEFAULT_RESULT_PATH = Path("/var/lib/lattice/backup-query-result.json")
DEFAULT_CREDENTIAL_ROOT = Path("/etc/lattice/backup/credentials")


class BackupQueryError(RuntimeError):
    pass


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupQueryError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupQueryError(f"{label} must be UUIDv4")
    return str(parsed)


def _request_path() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_QUERY_REQUEST_PATH", str(DEFAULT_REQUEST_PATH)))


def _result_path() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_QUERY_RESULT_PATH", str(DEFAULT_RESULT_PATH)))


def _atomic_write(path: Path, payload: dict, *, service_readable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o640 if service_readable else 0o600)
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if service_readable and os.geteuid() == 0:
            try:
                lattice_gid = grp.getgrnam("lattice").gr_gid
            except KeyError as exc:
                raise BackupQueryError("The lattice group is unavailable") from exc
            os.chown(temporary, 0, lattice_gid)
        os.replace(temporary, path)
        os.chmod(path, 0o640 if service_readable else 0o600)
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


def _safe_read(path: Path, *, maximum: int = 2_000_000) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BackupQueryError("Backup query path is unsafe")
        if metadata.st_mode & 0o022 or metadata.st_size > maximum:
            raise BackupQueryError("Backup query permissions or size are unsafe")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupQueryError("Backup query JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise BackupQueryError("Backup query must be an object")
    return payload


def _job(job_uuid: str) -> dict:
    job_uuid = _uuid4(job_uuid, "Backup job ID")
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT bj.id,bj.job_uuid,bj.source_node_id,bj.source_path,bj.enabled,bj.paused,
                      fn.hostname AS source_hostname,fn.main_user,fn.main_uid,fn.main_gid,
                      bt.host_node_id,bt.target_uuid,
                      bt.filesystem_uuid,bt.repository_root,bt.repository_relative_path,
                      bt.enabled AS target_enabled
               FROM backup_jobs bj
               JOIN fleet_nodes fn ON fn.node_id=bj.source_node_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE bj.job_uuid=?""",
            (job_uuid,),
        ).fetchone()
        if row is None:
            raise BackupQueryError("Backup job was not found")
        return dict(row)
    finally:
        conn.close()


def _validate_local_job(job: dict) -> str:
    identity = load_node_identity()
    if identity is None:
        raise BackupQueryError("Local Lattice node identity is unavailable")
    if job["source_node_id"] != identity.node_id:
        raise BackupQueryError("Backup job belongs to a different source computer")
    if not bool(job["enabled"]) or not bool(job["target_enabled"]):
        raise BackupQueryError("Backup job is unavailable")
    return identity.node_id


def queue_backup_query(
    job_uuid: str,
    operation: str,
    *,
    snapshot_id: str | None = None,
    directory: str | None = None,
) -> str:
    if operation not in {"snapshots", "directory", "recovery_preflight"}:
        raise BackupQueryError("Backup query operation is invalid")
    job = _job(job_uuid)
    _validate_local_job(job)
    if operation in {"directory", "recovery_preflight"}:
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise BackupQueryError("Snapshot ID is required")
    if operation == "directory":
        if not isinstance(directory, str) or not directory.startswith("/"):
            raise BackupQueryError("Snapshot directory is required")
        root = PurePosixPath(job["source_path"])
        candidate = PurePosixPath(directory)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise BackupQueryError("Snapshot browse path is outside the protected Home") from exc
        if ".." in candidate.parts:
            raise BackupQueryError("Snapshot browse path is unsafe")
    elif operation == "snapshots":
        snapshot_id = None
        directory = None
    else:
        directory = None

    request_path = _request_path()
    request_id = str(uuid.uuid4())
    payload = {
        "schema_version": 1,
        "request_id": request_id,
        "job_uuid": job["job_uuid"],
        "operation": operation,
        "snapshot_id": snapshot_id,
        "directory": directory,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    if not _atomic_create(request_path, payload):
        raise BackupQueryError("Another backup browse request is already pending")
    return request_id


def read_backup_query_result(request_id: str) -> dict | None:
    request_id = _uuid4(request_id, "Backup query request ID")
    path = _result_path()
    try:
        payload = _safe_read(path)
    except FileNotFoundError:
        return None
    if payload.get("request_id") != request_id:
        return None
    return payload


def _completed_snapshot_ids(job_id: int) -> set[str]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT DISTINCT snapshot_id FROM backup_runs
               WHERE job_id=? AND result='successful' AND snapshot_id IS NOT NULL""",
            (int(job_id),),
        ).fetchall()
    finally:
        conn.close()
    return {str(row[0]) for row in rows if row[0]}


def _repository_candidates(job: dict):
    try:
        password_file = validate_password_file(
            DEFAULT_CREDENTIAL_ROOT / f"{job['job_uuid']}.password"
        )
    except BackupCredentialError as exc:
        raise BackupQueryError(str(exc)) from exc
    identity = load_node_identity()
    if identity is None:
        raise BackupQueryError("Local Lattice node identity is unavailable")
    if job["host_node_id"] == identity.node_id:
        try:
            repository_root, _mount = resolve_repository_root(
                job["filesystem_uuid"], job["repository_relative_path"]
            )
        except BackupTargetError as exc:
            raise BackupQueryError(str(exc)) from exc
        yield ResticRepository(repository_root / identity.node_id, password_file)
        return
    try:
        connections = connection_candidates(job)
    except RemoteBackupError as exc:
        raise BackupQueryError(str(exc)) from exc
    for connection in connections:
        yield ResticSFTPRepository(
            connection.repository,
            password_file,
            ssh_args=connection.ssh_args,
        )


def _query_repository(job: dict, operation: str, snapshot_id: str | None, directory: str | None) -> dict:
    last_error: Exception | None = None
    for repo in _repository_candidates(job):
        try:
            snapshots = [
                item for item in repo.snapshots()
                if job["source_path"] in item.paths
            ]
            snapshots.sort(key=lambda item: item.time, reverse=True)
            completed_ids = _completed_snapshot_ids(int(job["id"]))
            if operation == "snapshots":
                return {
                    "source_root": job["source_path"],
                    "snapshots": [
                        {
                            "snapshot_id": item.snapshot_id,
                            "time": item.time,
                            "hostname": item.hostname,
                            "health": (
                                "completed"
                                if item.snapshot_id in completed_ids
                                else "unknown"
                            ),
                        }
                        for item in snapshots[:500]
                    ],
                }
            selected = next(
                (item for item in snapshots if item.snapshot_id == snapshot_id),
                None,
            )
            if selected is None:
                raise BackupQueryError("Selected snapshot is not part of this backup job")
            if operation == "recovery_preflight":
                stats = repo.snapshot_restore_stats(selected.snapshot_id)
                staging_root = Path(
                    os.environ.get(
                        "LATTICE_BACKUP_RESTORE_STAGING_ROOT",
                        str(DEFAULT_RECOVERY_STAGING_ROOT),
                    )
                )
                preflight = full_home_recovery_preflight(
                    job,
                    stats,
                    staging_root=staging_root,
                    snapshot_completed=selected.snapshot_id in completed_ids,
                )
                return {
                    "source_root": job["source_path"],
                    "snapshot_id": selected.snapshot_id,
                    "snapshot_time": selected.time,
                    "preflight": preflight,
                }
            assert directory is not None
            entries = repo.list_snapshot_directory(selected.snapshot_id, directory, limit=500)
            return {
                "source_root": job["source_path"],
                "directory": directory,
                "snapshot_id": selected.snapshot_id,
                "entries": [
                    {
                        "path": item.path,
                        "name": item.name,
                        "type": item.entry_type,
                        "size": item.size,
                        "modified_at": item.modified_at,
                    }
                    for item in entries
                ],
            }
        except (ResticError, BackupQueryError, BackupRecoveryError, OSError) as exc:
            last_error = exc
            continue
    raise BackupQueryError(str(last_error or "No backup repository route is available")) from last_error


def execute_backup_query() -> dict:
    if os.geteuid() != 0:
        raise BackupQueryError("Backup repository queries must run as root")
    request_path = _request_path()
    result: dict | None = None
    request_id: str | None = None
    job_uuid: str | None = None
    operation: object = None
    try:
        payload = _safe_read(request_path, maximum=65536)
        if payload.get("schema_version") != 1:
            raise BackupQueryError("Backup query schema is invalid")
        request_id = _uuid4(payload.get("request_id"), "Backup query request ID")
        job = _job(str(payload.get("job_uuid")))
        job_uuid = job["job_uuid"]
        _validate_local_job(job)
        operation = payload.get("operation")
        if operation not in {"snapshots", "directory", "recovery_preflight"}:
            raise BackupQueryError("Backup query operation is invalid")
        data = _query_repository(job, str(operation), payload.get("snapshot_id"), payload.get("directory"))
        result = {
            "request_id": request_id, "status": "successful",
            "job_uuid": job_uuid, "operation": operation, **data,
        }
        return result
    except Exception as exc:
        if request_id is not None:
            result = {
                "request_id": request_id, "status": "failed",
                "job_uuid": job_uuid, "operation": operation,
                "error": str(exc)[:1000],
            }
        if isinstance(exc, BackupQueryError):
            raise
        raise BackupQueryError(str(exc)) from exc
    finally:
        if result is not None:
            _atomic_write(_result_path(), result, service_readable=True)
        request_path.unlink(missing_ok=True)

def wait_for_query_result(request_id: str, *, timeout_seconds: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = read_backup_query_result(request_id)
        if result is not None:
            return result
        time.sleep(0.2)
    raise BackupQueryError("Timed out waiting for the source computer to browse its backup")


def main() -> None:
    result = execute_backup_query()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
