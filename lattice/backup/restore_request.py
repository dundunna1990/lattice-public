"""Narrow source-side request queue for staged and placed restores."""
from __future__ import annotations

from datetime import datetime, timezone
import grp
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import uuid

from lattice.backup.query import _job as query_job
from lattice.backup.restore_workflow import (
    BackupRestoreWorkflowError,
    cancel_restore,
    place_restore,
    stage_restore,
)
from lattice.file_access.identity import load_node_identity

DEFAULT_REQUEST_PATH = Path("/var/lib/lattice/backup-restore-request.json")
DEFAULT_RESULT_PATH = Path("/var/lib/lattice/backup-restore-result.json")


class BackupRestoreRequestError(RuntimeError):
    pass


def _request_path() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_RESTORE_REQUEST_PATH", str(DEFAULT_REQUEST_PATH)))


def _result_path() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_RESTORE_RESULT_PATH", str(DEFAULT_RESULT_PATH)))


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupRestoreRequestError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupRestoreRequestError(f"{label} must be UUIDv4")
    return str(parsed)


def _atomic_write(path: Path, payload: dict, *, service_readable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    mode = 0o640 if service_readable else 0o600
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), mode)
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if service_readable and os.geteuid() == 0:
            lattice_gid = grp.getgrnam("lattice").gr_gid
            os.chown(temporary, 0, lattice_gid)
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


def _safe_read(path: Path, *, maximum: int = 131072) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BackupRestoreRequestError("Restore request path is unsafe")
        if metadata.st_mode & 0o022 or metadata.st_size > maximum:
            raise BackupRestoreRequestError("Restore request permissions or size are unsafe")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupRestoreRequestError("Restore request JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise BackupRestoreRequestError("Restore request must be an object")
    return payload


def _validate_local_job(job_uuid: str) -> None:
    job = query_job(job_uuid)
    identity = load_node_identity()
    if identity is None:
        raise BackupRestoreRequestError("Local Lattice node identity is unavailable")
    if job["source_node_id"] != identity.node_id:
        raise BackupRestoreRequestError("Restore belongs to a different source computer")
    if not bool(job["enabled"]) or not bool(job["target_enabled"]):
        raise BackupRestoreRequestError("Backup job is unavailable")


def queue_restore_request(
    operation: str,
    *,
    job_uuid: str | None = None,
    snapshot_id: str | None = None,
    selection: str | None = None,
    session_uuid: str | None = None,
    choice: str | None = None,
    elsewhere: str | None = None,
) -> str:
    if operation not in {"stage", "place", "cancel"}:
        raise BackupRestoreRequestError("Restore request operation is invalid")
    payload: dict = {"schema_version": 1, "operation": operation}
    if operation == "stage":
        if not isinstance(job_uuid, str):
            raise BackupRestoreRequestError("Backup job ID is required")
        _validate_local_job(job_uuid)
        if not isinstance(snapshot_id, str) or not snapshot_id or len(snapshot_id) > 128:
            raise BackupRestoreRequestError("Snapshot ID is invalid")
        if not isinstance(selection, str) or not selection.startswith("/") or len(selection) > 4096:
            raise BackupRestoreRequestError("Restore selection is invalid")
        payload.update({
            "job_uuid": job_uuid,
            "snapshot_id": snapshot_id,
            "selection": selection,
        })
    else:
        session_uuid = _uuid4(session_uuid, "Restore session ID")
        payload["session_uuid"] = session_uuid
        if operation == "place":
            if choice not in {"keep_both", "replace", "elsewhere"}:
                raise BackupRestoreRequestError("Restore placement choice is invalid")
            if choice == "elsewhere" and (
                not isinstance(elsewhere, str) or not elsewhere.startswith("/") or len(elsewhere) > 4096
            ):
                raise BackupRestoreRequestError("Alternate restore destination is invalid")
            payload.update({"choice": choice, "elsewhere": elsewhere})
    request_path = _request_path()
    request_id = str(uuid.uuid4())
    payload.update({
        "request_id": request_id,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    })
    if not _atomic_create(request_path, payload):
        raise BackupRestoreRequestError("Another restore request is already pending")
    return request_id


def read_restore_result(request_id: str) -> dict | None:
    request_id = _uuid4(request_id, "Restore request ID")
    try:
        payload = _safe_read(_result_path(), maximum=262144)
    except FileNotFoundError:
        return None
    return payload if payload.get("request_id") == request_id else None


def execute_restore_request() -> dict:
    if os.geteuid() != 0:
        raise BackupRestoreRequestError("Restore execution must run as root")
    request_path = _request_path()
    output: dict | None = None
    request_id: str | None = None
    operation: object = None
    try:
        payload = _safe_read(request_path)
        if payload.get("schema_version") != 1:
            raise BackupRestoreRequestError("Restore request schema is invalid")
        request_id = _uuid4(payload.get("request_id"), "Restore request ID")
        operation = payload.get("operation")
        if operation == "stage":
            result = stage_restore(
                str(payload.get("job_uuid")), str(payload.get("snapshot_id")),
                str(payload.get("selection")),
            )
        elif operation == "place":
            result = place_restore(
                str(payload.get("session_uuid")), str(payload.get("choice")),
                elsewhere=payload.get("elsewhere"),
            )
        elif operation == "cancel":
            result = cancel_restore(str(payload.get("session_uuid")))
        else:
            raise BackupRestoreRequestError("Restore request operation is invalid")
        output = {"request_id": request_id, **result, "status": "successful"}
        return output
    except Exception as exc:
        if request_id is not None:
            output = {
                "request_id": request_id, "status": "failed",
                "operation": operation, "error": str(exc)[:1000],
            }
        if isinstance(exc, BackupRestoreRequestError):
            raise
        raise BackupRestoreRequestError(str(exc)) from exc
    finally:
        if output is not None:
            _atomic_write(_result_path(), output, service_readable=True)
        request_path.unlink(missing_ok=True)

def wait_for_restore_result(request_id: str, *, timeout_seconds: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        result = read_restore_result(request_id)
        if result is not None:
            return result
        time.sleep(0.25)
    raise BackupRestoreRequestError("Timed out waiting for restore operation")


def main() -> None:
    result = execute_restore_request()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
