"""Protected Restic repository credential helpers."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import stat
import tempfile


class BackupCredentialError(RuntimeError):
    pass


def validate_password_file(path: Path) -> Path:
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise BackupCredentialError("Backup credential file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BackupCredentialError("Backup credential must be a regular non-symlink file")
    if info.st_mode & 0o077:
        raise BackupCredentialError("Backup credential permissions are too broad")
    if info.st_size < 20 or info.st_size > 4096:
        raise BackupCredentialError("Backup credential has an unsafe size")
    return path


def create_password_file(path: Path) -> Path:
    """Atomically create one strong Restic password without replacing an existing key."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.is_symlink():
        return validate_password_file(path)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        secret = secrets.token_urlsafe(48).encode("ascii") + b"\n"
        os.write(fd, secret)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(temporary, path)
        except FileExistsError:
            return validate_password_file(path)
        return validate_password_file(path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
