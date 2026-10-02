"""Hard safety boundaries for Daily Care."""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path

PROTECTED_ROOTS = (Path("/home"), Path("/root"), Path("/mnt/lattice"))
BACKUP_LOCK_ROOT = Path("/run/lattice/backup-locks")
CARE_LOCK_PATH = Path("/run/lattice/care.lock")


class CareSafetyError(RuntimeError):
    pass


def assert_allowed_delete(path: Path, *, allowed_parent: Path) -> Path:
    path = Path(path)
    allowed_parent = Path(allowed_parent).resolve(strict=False)
    if not path.is_absolute():
        raise CareSafetyError("Daily Care deletion path must be absolute")
    lexical = Path(os.path.normpath(str(path)))
    for protected in PROTECTED_ROOTS:
        protected_norm = Path(os.path.normpath(str(protected)))
        if lexical == protected_norm or protected_norm in lexical.parents:
            raise CareSafetyError(f"Daily Care refuses protected path {lexical}")
    if path.is_symlink():
        raise CareSafetyError("Daily Care never follows or deletes symbolic links")
    resolved = path.resolve(strict=False)
    for protected in PROTECTED_ROOTS:
        protected_resolved = protected.resolve(strict=False)
        if resolved == protected_resolved or protected_resolved in resolved.parents:
            raise CareSafetyError(f"Daily Care refuses protected path {resolved}")
    if resolved.parent != allowed_parent:
        raise CareSafetyError("Daily Care path escaped its named cleanup directory")
    return resolved


@contextmanager
def care_run_lock():
    path = Path(os.environ.get("LATTICE_CARE_LOCK_PATH", str(CARE_LOCK_PATH)))
    if not path.is_absolute():
        raise CareSafetyError("Daily Care lock path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CareSafetyError("Could not open Daily Care run lock") from exc
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_nlink != 1 or metadata.st_mode & 0o077:
            raise CareSafetyError("Daily Care run lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CareSafetyError("Daily Care is already running") from exc
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        try:
            yield path
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def backup_work_active(lock_root: Path = BACKUP_LOCK_ROOT) -> bool:
    if not lock_root.exists():
        return False
    if lock_root.is_symlink() or not lock_root.is_dir():
        return True
    for path in lock_root.glob("*.lock"):
        try:
            fd = os.open(
                path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
        except OSError:
            return True
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            finally:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(fd)
    return False
