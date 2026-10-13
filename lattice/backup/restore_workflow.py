"""Staged, explicit-conflict restore workflow for source-owned Home backups."""
from __future__ import annotations

from datetime import datetime, timezone
import ctypes
import errno
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
import uuid

from lattice.backup.query import _job as query_job, _repository_candidates
from lattice.backup.locks import BackupLockError, repository_operation_lock
from lattice.backup.restic import ResticError
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

DEFAULT_STAGING_ROOT = Path("/var/lib/lattice/backup/restore-staging")


class BackupRestoreWorkflowError(RuntimeError):
    pass


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupRestoreWorkflowError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupRestoreWorkflowError(f"{label} must be UUIDv4")
    return str(parsed)


def _validate_source_job(job: dict) -> str:
    identity = load_node_identity()
    if identity is None:
        raise BackupRestoreWorkflowError("Local Lattice node identity is unavailable")
    if job["source_node_id"] != identity.node_id:
        raise BackupRestoreWorkflowError("Restore belongs to a different source computer")
    if not bool(job["enabled"]) or not bool(job["target_enabled"]):
        raise BackupRestoreWorkflowError("Backup job is unavailable")
    return identity.node_id


def _selection(job: dict, value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise BackupRestoreWorkflowError("Restore selection must be an absolute backup path")
    source_root = PurePosixPath(job["source_path"])
    selected = PurePosixPath(value)
    if ".." in selected.parts:
        raise BackupRestoreWorkflowError("Restore selection is unsafe")
    try:
        selected.relative_to(source_root)
    except ValueError as exc:
        raise BackupRestoreWorkflowError("Restore selection is outside the protected Home") from exc
    return selected


def _safe_home_destination(job: dict, value: str) -> Path:
    selected = _selection(job, value)
    destination = Path(str(selected))
    home = Path(job["source_path"])
    # Do not follow existing symlink components. A restore destination may not
    # tunnel out of Home through a pre-existing symlink.
    current = home
    if current.is_symlink():
        raise BackupRestoreWorkflowError("Protected Home path is an unsafe symlink")
    relative = selected.relative_to(PurePosixPath(job["source_path"]))
    for part in relative.parts:
        current = current / part
        if current.exists() or current.is_symlink():
            if current.is_symlink():
                raise BackupRestoreWorkflowError(
                    "Restore destination crosses an existing symbolic link"
                )
    resolved_home = home.resolve(strict=False)
    resolved_parent = destination.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(resolved_home)
    except ValueError as exc:
        raise BackupRestoreWorkflowError("Restore destination escaped the protected Home") from exc
    return destination


def _snapshot_exists(repo, job: dict, snapshot_id: str) -> str:
    snapshots = [item for item in repo.snapshots() if job["source_path"] in item.paths]
    match = next((item for item in snapshots if item.snapshot_id == snapshot_id), None)
    if match is None:
        raise BackupRestoreWorkflowError("Selected snapshot is not part of this backup job")
    return match.snapshot_id


def _staging_root() -> Path:
    return Path(os.environ.get("LATTICE_BACKUP_RESTORE_STAGING_ROOT", str(DEFAULT_STAGING_ROOT)))


def _create_staging(session_uuid: str) -> Path:
    root = _staging_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    path = root / session_uuid
    path.mkdir(mode=0o700)
    return path


def _restored_object(staging: Path, selection: PurePosixPath) -> Path:
    candidate = staging.joinpath(*selection.parts[1:])
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(staging.resolve(strict=False))
    except ValueError as exc:
        raise BackupRestoreWorkflowError("Staged restore escaped its protected directory") from exc
    if not candidate.exists() and not candidate.is_symlink():
        raise BackupRestoreWorkflowError("Restic completed but the selected object was not staged")
    return candidate


def _describe(path: Path) -> dict:
    metadata = path.lstat()
    if stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
        size = 0
    elif stat.S_ISREG(metadata.st_mode):
        kind = "file"
        size = int(metadata.st_size)
    elif stat.S_ISLNK(metadata.st_mode):
        kind = "symlink"
        size = 0
    else:
        kind = "other"
        size = int(metadata.st_size)
    return {"type": kind, "size": size}


def _stage_restore_unlocked(job_uuid: str, snapshot_id: str, selection: str) -> dict:
    job = query_job(job_uuid)
    _validate_source_job(job)
    selected = _selection(job, selection)
    original = _safe_home_destination(job, str(selected))
    session_uuid = str(uuid.uuid4())
    staging = _create_staging(session_uuid)
    last_error: Exception | None = None
    try:
        for repo in _repository_candidates(job):
            try:
                actual_snapshot = _snapshot_exists(repo, job, snapshot_id)
                repo.restore_to_staging(actual_snapshot, staging, include=str(selected))
                staged_object = _restored_object(staging, selected)
                description = _describe(staged_object)
                conflict = original.exists() or original.is_symlink()
                conn = get_db_connection()
                try:
                    conn.execute(
                        """INSERT INTO backup_restore_sessions(
                               session_uuid,job_id,snapshot_id,selection_path,staging_path,
                               original_destination,state,conflict)
                           VALUES(?,?,?,?,?,?,'staged',?)""",
                        (
                            session_uuid, int(job["id"]), actual_snapshot,
                            str(selected), str(staging), str(original), 1 if conflict else 0,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
                return {
                    "status": "staged",
                    "session_uuid": session_uuid,
                    "job_uuid": job_uuid,
                    "snapshot_id": actual_snapshot,
                    "selection": str(selected),
                    "name": selected.name or str(selected),
                    "type": description["type"],
                    "size": description["size"],
                    "conflict": conflict,
                    "original_destination": str(original),
                }
            except (ResticError, BackupRestoreWorkflowError, OSError) as exc:
                last_error = exc
                # A failed route may have left a partial restore tree. Never
                # let the next LAN route reuse or merge with that partial data.
                shutil.rmtree(staging, ignore_errors=True)
                staging.mkdir(mode=0o700)
                continue
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    shutil.rmtree(staging, ignore_errors=True)
    raise BackupRestoreWorkflowError(str(last_error or "Could not stage the selected backup")) from last_error



def stage_restore(job_uuid: str, snapshot_id: str, selection: str) -> dict:
    job = query_job(job_uuid)
    _validate_source_job(job)
    try:
        with repository_operation_lock(job["job_uuid"], "restore"):
            return _stage_restore_unlocked(job_uuid, snapshot_id, selection)
    except BackupLockError as exc:
        raise BackupRestoreWorkflowError(str(exc)) from exc

def _session(session_uuid: str) -> dict:
    session_uuid = _uuid4(session_uuid, "Restore session ID")
    conn = get_db_connection()
    try:
        row = conn.execute(
            """SELECT rs.*,bj.source_node_id,bj.source_path,bj.enabled,
                      bt.enabled AS target_enabled
               FROM backup_restore_sessions rs
               JOIN backup_jobs bj ON bj.id=rs.job_id
               JOIN backup_targets bt ON bt.id=bj.target_id
               WHERE rs.session_uuid=?""",
            (session_uuid,),
        ).fetchone()
        if row is None:
            raise BackupRestoreWorkflowError("Restore session was not found")
        return dict(row)
    finally:
        conn.close()


def _validated_staging_path(session: dict) -> Path:
    session_uuid = _uuid4(session.get("session_uuid"), "Restore session ID")
    root = _staging_root().resolve(strict=False)
    staging = Path(str(session.get("staging_path") or ""))
    expected = root / session_uuid
    if staging != expected:
        raise BackupRestoreWorkflowError("Restore staging path does not match its protected session directory")
    if staging.is_symlink():
        raise BackupRestoreWorkflowError("Restore staging path is an unsafe symlink")
    try:
        staging.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise BackupRestoreWorkflowError("Restore staging path is outside Lattice staging") from exc
    return staging


def _staged_source(session: dict) -> Path:
    staging = _validated_staging_path(session)
    selected = PurePosixPath(session["selection_path"])
    return _restored_object(staging, selected)


def _keep_both_destination(original: Path) -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d %H%M%S")
    stem = original.name
    parent = original.parent
    candidate = parent / f"{stem} (restored {timestamp})"
    index = 2
    while candidate.exists() or candidate.is_symlink():
        candidate = parent / f"{stem} (restored {timestamp}) {index}"
        index += 1
        if index > 1000:
            raise BackupRestoreWorkflowError("Could not choose a safe Keep Both filename")
    return candidate


def _copy_archive(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["/bin/cp", "--archive", "--reflink=auto", "--", str(source), str(destination)],
            capture_output=True, text=True, timeout=7200,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupRestoreWorkflowError(f"Could not place restored data: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "copy failed").strip()
        raise BackupRestoreWorkflowError(f"Could not place restored data: {detail[:1000]}")


def _remove_placement_artifact(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically place a restore only if the destination is still unused.

    Lattice supports Linux only. renameat2(RENAME_NOREPLACE) closes the
    check-then-rename race that would otherwise let Keep Both/Elsewhere
    overwrite a file created after the destination was selected.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise BackupRestoreWorkflowError(
            "Safe no-overwrite restore placement is unavailable on this system"
        )
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,  # AT_FDCWD
        os.fsencode(source),
        -100,  # AT_FDCWD
        os.fsencode(destination),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise BackupRestoreWorkflowError(
            "Restore destination appeared during placement; nothing was overwritten"
        )
    raise BackupRestoreWorkflowError(
        f"Could not safely place restored data: {os.strerror(error)}"
    )


def _recover_interrupted_replace(
    destination: Path, rollback_path: Path, temporary_destination: Path
) -> None:
    """Recover the unambiguous pre-commit phases of an interrupted replacement."""
    rollback_exists = rollback_path.exists() or rollback_path.is_symlink()
    destination_exists = destination.exists() or destination.is_symlink()
    if rollback_exists and destination_exists:
        raise BackupRestoreWorkflowError(
            "Interrupted restore left both original and replacement data; "
            "refusing to choose between them automatically"
        )
    if rollback_exists:
        _remove_placement_artifact(temporary_destination)
        try:
            os.replace(rollback_path, destination)
        except OSError as exc:
            raise BackupRestoreWorkflowError(
                "Could not recover the original destination from an interrupted restore"
            ) from exc
        return
    _remove_placement_artifact(temporary_destination)


def place_restore(
    session_uuid: str,
    choice: str,
    *,
    elsewhere: str | None = None,
) -> dict:
    if choice not in {"keep_both", "replace", "elsewhere"}:
        raise BackupRestoreWorkflowError("Restore placement choice is invalid")
    session = _session(session_uuid)
    _validate_source_job(session)
    if session["state"] != "staged":
        raise BackupRestoreWorkflowError("Restore session is no longer waiting for placement")
    source = _staged_source(session)
    original = _safe_home_destination(session, session["original_destination"])
    if choice == "keep_both":
        destination = _keep_both_destination(original)
    elif choice == "elsewhere":
        if elsewhere is None:
            raise BackupRestoreWorkflowError("Alternate restore destination is required")
        destination = _safe_home_destination(session, elsewhere)
        if destination.exists() or destination.is_symlink():
            raise BackupRestoreWorkflowError(
                "Alternate restore destination already exists; choose a new location"
            )
    else:
        destination = original

    rollback_path: Path | None = None
    temporary_destination = destination.parent / f".lattice-restore-new-{session_uuid}"
    if choice == "replace":
        rollback_path = destination.parent / f".lattice-restore-replaced-{session_uuid}"
        _recover_interrupted_replace(destination, rollback_path, temporary_destination)
    else:
        _remove_placement_artifact(temporary_destination)
    try:
        if choice == "replace" and (destination.exists() or destination.is_symlink()):
            assert rollback_path is not None
            os.replace(destination, rollback_path)
        _copy_archive(source, temporary_destination)
        if choice == "replace":
            os.replace(temporary_destination, destination)
        else:
            _rename_noreplace(temporary_destination, destination)
    except Exception:
        try:
            if temporary_destination.is_dir() and not temporary_destination.is_symlink():
                shutil.rmtree(temporary_destination)
            else:
                temporary_destination.unlink(missing_ok=True)
        except OSError:
            pass
        if rollback_path is not None and (rollback_path.exists() or rollback_path.is_symlink()):
            try:
                if destination.exists() or destination.is_symlink():
                    if destination.is_dir() and not destination.is_symlink():
                        shutil.rmtree(destination)
                    else:
                        destination.unlink(missing_ok=True)
                os.replace(rollback_path, destination)
            except OSError:
                pass
        raise

    staging = _validated_staging_path(session)
    # Commit the durable terminal state before deleting the only staged copy.
    # If SQLite fails here the complete staging tree is preserved, allowing an
    # operator/recovery path to inspect or retry instead of losing both the
    # session state and its retry source.
    conn = get_db_connection()
    try:
        conn.execute(
            """UPDATE backup_restore_sessions
               SET state='placed',placed_destination=?,updated_at=CURRENT_TIMESTAMP
               WHERE session_uuid=?""",
            (str(destination), session_uuid),
        )
        conn.commit()
    finally:
        conn.close()

    # The database now durably records completion. Only now is it safe to
    # discard the original-data rollback copy. A cleanup failure is harmless:
    # preserving an extra hidden copy is safer than risking data loss.
    if rollback_path is not None:
        try:
            _remove_placement_artifact(rollback_path)
        except OSError:
            pass

    shutil.rmtree(staging, ignore_errors=True)
    return {
        "status": "placed",
        "session_uuid": session_uuid,
        "destination": str(destination),
        "choice": choice,
    }


def cancel_restore(session_uuid: str) -> dict:
    session = _session(session_uuid)
    _validate_source_job(session)
    if session["state"] == "staged":
        staging = _validated_staging_path(session)
        shutil.rmtree(staging, ignore_errors=True)
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE backup_restore_sessions SET state='cancelled',updated_at=CURRENT_TIMESTAMP WHERE session_uuid=?",
                (session_uuid,),
            )
            conn.commit()
        finally:
            conn.close()
    return {"status": "cancelled", "session_uuid": session_uuid}


def cleanup_restore_staging(
    *,
    orphan_age_seconds: int = 7 * 24 * 60 * 60,
    now_timestamp: float | None = None,
) -> dict:
    """Remove only provably stale restore staging without touching live sessions."""
    if (
        isinstance(orphan_age_seconds, bool)
        or not isinstance(orphan_age_seconds, int)
        or orphan_age_seconds < 3600
    ):
        raise BackupRestoreWorkflowError("Restore staging cleanup age is invalid")
    root = _staging_root()
    if not root.exists():
        return {"removed_terminal": 0, "removed_orphan": 0, "preserved_staged": 0}
    if root.is_symlink() or not root.is_dir():
        raise BackupRestoreWorkflowError("Restore staging root is unsafe")

    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT session_uuid,state,staging_path FROM backup_restore_sessions"
        ).fetchall()
    finally:
        conn.close()
    sessions = {str(row["session_uuid"]): dict(row) for row in rows}
    request_path = Path(
        os.environ.get(
            "LATTICE_BACKUP_RESTORE_REQUEST_PATH",
            "/var/lib/lattice/backup-restore-request.json",
        )
    )
    try:
        active_request = request_path.exists()
    except OSError:
        # If request state cannot be inspected, assume a restore may be active.
        # This fails closed for orphan cleanup while still allowing cleanup of
        # DB-known terminal sessions below.
        active_request = True
    now_value = float(now_timestamp) if now_timestamp is not None else datetime.now().timestamp()
    removed_terminal = removed_orphan = preserved_staged = 0

    for child in root.iterdir():
        if child.is_symlink() or not child.is_dir():
            continue
        try:
            parsed = uuid.UUID(child.name)
        except ValueError:
            continue
        if parsed.version != 4 or str(parsed) != child.name:
            continue
        session = sessions.get(child.name)
        if session is not None:
            expected = Path(str(session["staging_path"]))
            if expected != child:
                # DB/path disagreement is not something maintenance should fix destructively.
                continue
            if session["state"] == "staged":
                preserved_staged += 1
                continue
            if session["state"] in {"placed", "cancelled", "failed"}:
                shutil.rmtree(child)
                removed_terminal += 1
            continue
        if active_request:
            continue
        try:
            age = now_value - child.stat().st_mtime
        except OSError:
            continue
        if age >= orphan_age_seconds:
            shutil.rmtree(child)
            removed_orphan += 1

    return {
        "removed_terminal": removed_terminal,
        "removed_orphan": removed_orphan,
        "preserved_staged": preserved_staged,
    }
