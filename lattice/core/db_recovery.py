"""Conservative SQLite backup and recovery helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import tempfile


class DatabaseRecoveryError(RuntimeError):
    pass


def database_path() -> Path:
    value = os.environ.get("LATTICE_DB_PATH")
    if not value:
        raise DatabaseRecoveryError(
            "LATTICE_DB_PATH is not configured"
        )
    return Path(value)


def verify_database(path: Path | None = None) -> bool:
    """Return True only for a SQLite DB whose quick_check reports ok."""
    path = Path(path or database_path())

    if not path.exists():
        return True

    try:
        conn = sqlite3.connect(
            f"file:{path}?mode=ro",
            uri=True,
            timeout=5,
        )
        try:
            row = conn.execute(
                "PRAGMA quick_check"
            ).fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return False

    return (
        row is not None
        and len(row) > 0
        and str(row[0]).lower() == "ok"
    )


def _backup_directory(
    source: Path,
    backup_dir: Path | None,
) -> Path:
    if backup_dir is not None:
        result = Path(backup_dir)
    else:
        result = source.parent / "backups"

    result.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )
    return result


def create_verified_backup(
    source: Path | None = None,
    backup_dir: Path | None = None,
    keep: int = 5,
) -> Path | None:
    """Create one consistent SQLite online backup and verify it."""
    source = Path(source or database_path())

    if not source.exists():
        return None

    if not verify_database(source):
        raise DatabaseRecoveryError(
            "Primary Lattice database failed integrity verification; "
            "refusing to create a backup from corrupt state"
        )

    directory = _backup_directory(
        source,
        backup_dir,
    )

    stamp = (
        datetime.now(timezone.utc)
        .strftime("%Y%m%dT%H%M%S.%fZ")
    )

    destination = directory / (
        f"{source.name}.{stamp}.sqlite"
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{source.name}.backup.",
        suffix=".tmp",
        dir=directory,
    )
    os.close(fd)

    temporary = Path(temporary_name)

    try:
        src = sqlite3.connect(
            str(source),
            timeout=5,
        )
        dst = sqlite3.connect(
            str(temporary),
            timeout=5,
        )

        try:
            src.backup(dst)
            dst.commit()
        finally:
            dst.close()
            src.close()

        if not verify_database(temporary):
            raise DatabaseRecoveryError(
                "New SQLite backup failed integrity verification"
            )

        os.chmod(temporary, 0o640)
        os.replace(
            temporary,
            destination,
        )

        # Keep a small rolling set.
        backups = sorted(
            directory.glob(
                f"{source.name}.*.sqlite"
            ),
            key=lambda item: item.stat().st_mtime_ns,
            reverse=True,
        )

        for obsolete in backups[max(1, keep):]:
            obsolete.unlink(missing_ok=True)

        return destination

    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def restore_verified_backup(
    backup: Path,
    destination: Path | None = None,
) -> Path:
    """Explicitly replace the DB only from a verified backup.

    If a destination already exists it is preserved beside it as a
    .corrupt/.replaced recovery artifact before the verified copy is installed.
    """
    backup = Path(backup)
    destination = Path(
        destination or database_path()
    )

    if not verify_database(backup):
        raise DatabaseRecoveryError(
            "Requested database backup failed integrity verification"
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.restore.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(fd)

    temporary = Path(temporary_name)

    try:
        source = sqlite3.connect(
            f"file:{backup}?mode=ro",
            uri=True,
            timeout=5,
        )
        target = sqlite3.connect(
            str(temporary),
            timeout=5,
        )

        try:
            source.backup(target)
            target.commit()
        finally:
            target.close()
            source.close()

        if not verify_database(temporary):
            raise DatabaseRecoveryError(
                "Restored database copy failed integrity verification"
            )

        if destination.exists():
            stamp = (
                datetime.now(timezone.utc)
                .strftime("%Y%m%dT%H%M%SZ")
            )
            preserved = destination.with_name(
                f"{destination.name}.replaced-{stamp}"
            )
            os.replace(
                destination,
                preserved,
            )

        os.chmod(temporary, 0o640)
        os.replace(
            temporary,
            destination,
        )

        return destination

    except Exception:
        temporary.unlink(missing_ok=True)
        raise
