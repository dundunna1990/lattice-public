"""Cross-process repository operation locks for Lattice Backup."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import uuid

DEFAULT_LOCK_ROOT = Path("/run/lattice/backup-locks")


class BackupLockError(RuntimeError):
    pass


def _uuid4(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupLockError("Backup job ID is invalid") from exc
    if parsed.version != 4:
        raise BackupLockError("Backup job ID must be UUIDv4")
    return str(parsed)


def _lock_root() -> Path:
    override = os.environ.get("LATTICE_BACKUP_LOCK_ROOT")
    if override:
        root = Path(override)
        if not root.is_absolute():
            raise BackupLockError("Backup lock root must be absolute")
        return root
    if os.geteuid() != 0:
        # Unit/development processes do not own /run/lattice. Production
        # backup/maintenance/restore services execute as root and always use
        # the runtime lock directory above.
        db_path = os.environ.get("LATTICE_DB_PATH")
        if db_path and Path(db_path).is_absolute():
            return Path(db_path).parent / "backup-locks"
    return DEFAULT_LOCK_ROOT


@contextmanager
def repository_operation_lock(job_uuid: str, operation: str):
    """Hold one non-blocking exclusive lock for a job/repository operation."""
    job_uuid = _uuid4(job_uuid)
    if not isinstance(operation, str) or operation not in {
        "backup", "maintenance", "restore"
    }:
        raise BackupLockError("Backup repository operation is invalid")
    root = _lock_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(root, 0o700)
    except OSError as exc:
        raise BackupLockError("Could not secure backup repository lock directory") from exc
    path = root / f"{job_uuid}.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BackupLockError("Could not open backup repository operation lock") from exc
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise BackupLockError("Backup repository operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BackupLockError(
                "Backup repository is busy with another backup, verification, maintenance, or restore"
            ) from exc
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()} {operation}\n".encode("ascii"))
        os.fsync(descriptor)
        try:
            yield path
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
