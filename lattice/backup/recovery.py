"""Read-only Full Home Recovery preflight helpers."""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import shutil
import stat

from lattice.backup.models import BackupSnapshotStats


DEFAULT_RECOVERY_STAGING_ROOT = Path("/var/lib/lattice/backup/restore-staging")


class BackupRecoveryError(RuntimeError):
    pass


def _existing_anchor(path: Path) -> Path:
    current = path
    while not current.exists():
        if current.parent == current:
            raise BackupRecoveryError("Could not locate an existing filesystem anchor")
        current = current.parent
    return current


def _filesystem_info(path: Path) -> dict:
    anchor = _existing_anchor(path)
    try:
        usage = shutil.disk_usage(anchor)
        device = os.stat(anchor, follow_symlinks=False).st_dev
    except OSError as exc:
        raise BackupRecoveryError(f"Could not inspect filesystem capacity for {path}") from exc
    return {
        "anchor": str(anchor),
        "device": int(device),
        "total_bytes": int(usage.total),
        "free_bytes": int(usage.free),
    }




def _account_info(username: str) -> dict:
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        return {"present": False, "uid": None, "gid": None}
    return {
        "present": True,
        "uid": int(account.pw_uid),
        "gid": int(account.pw_gid),
    }


def _home_info(path: Path) -> dict:
    exists = path.exists() or path.is_symlink()
    if not exists:
        return {
            "exists": False, "is_directory": False, "is_symlink": False,
            "uid": None, "gid": None,
        }
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise BackupRecoveryError("Could not inspect the current Home directory") from exc
    return {
        "exists": True,
        "is_directory": stat.S_ISDIR(metadata.st_mode),
        "is_symlink": stat.S_ISLNK(metadata.st_mode),
        "uid": int(metadata.st_uid),
        "gid": int(metadata.st_gid),
    }

def full_home_recovery_preflight(
    job: dict,
    stats: BackupSnapshotStats,
    *,
    staging_root: Path,
    snapshot_completed: bool,
    filesystem_inspector=_filesystem_info,
    account_inspector=_account_info,
    home_inspector=_home_info,
) -> dict:
    """Assess whether the current staged restore architecture can safely recover Home.

    This is intentionally non-destructive. It does not stage or place any data.
    """
    if not isinstance(stats, BackupSnapshotStats):
        raise BackupRecoveryError("Backup recovery statistics are invalid")
    if stats.total_size < 0 or stats.total_file_count < 0:
        raise BackupRecoveryError("Backup recovery statistics are invalid")
    if not isinstance(snapshot_completed, bool):
        raise BackupRecoveryError("Backup snapshot verification state is invalid")

    source_path = Path(str(job.get("source_path") or ""))
    if not source_path.is_absolute() or source_path.parent != Path("/home"):
        raise BackupRecoveryError("Full Home Recovery requires an exact /home/<user> source")
    expected_user = str(job.get("main_user") or "")
    expected_uid = job.get("main_uid")
    expected_gid = job.get("main_gid")
    if not expected_user:
        raise BackupRecoveryError("Backup source account name is unavailable")
    if isinstance(expected_uid, bool) or not isinstance(expected_uid, int) or expected_uid < 0:
        raise BackupRecoveryError("Backup source UID is invalid")
    if isinstance(expected_gid, bool) or not isinstance(expected_gid, int) or expected_gid < 0:
        raise BackupRecoveryError("Backup source GID is invalid")

    account = account_inspector(expected_user)
    if not isinstance(account, dict):
        raise BackupRecoveryError("Backup source account inspection is invalid")
    account_present = bool(account.get("present"))
    account_uid = account.get("uid")
    account_gid = account.get("gid")

    home = home_inspector(source_path)
    if not isinstance(home, dict):
        raise BackupRecoveryError("Current Home inspection is invalid")
    source_exists = bool(home.get("exists"))
    source_is_directory = bool(home.get("is_directory"))
    source_is_symlink = bool(home.get("is_symlink"))
    source_uid = home.get("uid")
    source_gid = home.get("gid")

    staging_fs = filesystem_inspector(Path(staging_root))
    home_fs = filesystem_inspector(source_path.parent)
    same_filesystem = staging_fs["device"] == home_fs["device"]
    restore_bytes = int(stats.total_size)

    # Current restore architecture keeps staged data until placement finishes.
    # Same filesystem therefore needs room for both staged and placed copies.
    if same_filesystem:
        required_staging_free = restore_bytes * 2
        required_home_free = required_staging_free
        space_ok = staging_fs["free_bytes"] >= required_staging_free
    else:
        required_staging_free = restore_bytes
        required_home_free = restore_bytes
        space_ok = (
            staging_fs["free_bytes"] >= required_staging_free
            and home_fs["free_bytes"] >= required_home_free
        )

    account_matches_expected = (
        account_present
        and account_uid == expected_uid
        and account_gid == expected_gid
    )
    current_home_matches_expected = (
        source_exists
        and source_is_directory
        and not source_is_symlink
        and source_uid == expected_uid
        and source_gid == expected_gid
    )

    blockers: list[str] = []
    warnings: list[str] = []
    if not snapshot_completed:
        blockers.append("This snapshot is not recorded as a completed Lattice backup")
    if not account_present:
        blockers.append(f"Linux account {expected_user} does not exist on this computer")
    elif not account_matches_expected:
        blockers.append(
            f"Linux account {expected_user} UID/GID does not match the backed-up source identity"
        )
    if source_is_symlink:
        blockers.append("Current Home path is a symbolic link")
    elif source_exists and not source_is_directory:
        blockers.append("Current Home path is not a directory")
    elif source_exists and not current_home_matches_expected:
        blockers.append("Current Home directory ownership does not match the expected account")
    if not space_ok:
        blockers.append("There is not enough free space for protected staged Full Home Recovery")
    if restore_bytes == 0:
        warnings.append("Snapshot reports zero restore bytes; verify this snapshot before recovery")
    if source_exists:
        warnings.append(
            "The current Home directory exists; live wholesale replacement remains intentionally disabled"
        )

    return {
        "ready_for_offline_recovery": not blockers,
        "live_replacement_allowed": False,
        "requires_offline_recovery": True,
        "source_path": str(source_path),
        "source_user": expected_user,
        "expected_uid": expected_uid,
        "expected_gid": expected_gid,
        "account_present": account_present,
        "account_uid": account_uid,
        "account_gid": account_gid,
        "account_matches_expected": account_matches_expected,
        "current_home_exists": source_exists,
        "current_home_is_directory": source_is_directory,
        "current_home_is_symlink": source_is_symlink,
        "current_home_uid": source_uid,
        "current_home_gid": source_gid,
        "current_home_matches_expected": current_home_matches_expected,
        "snapshot_completed": snapshot_completed,
        "snapshot_restore_bytes": restore_bytes,
        "snapshot_file_count": int(stats.total_file_count),
        "staging_free_bytes": staging_fs["free_bytes"],
        "home_free_bytes": home_fs["free_bytes"],
        "staging_and_home_same_filesystem": same_filesystem,
        "required_staging_free_bytes": required_staging_free,
        "required_home_free_bytes": required_home_free,
        "space_ok": space_ok,
        "blockers": blockers,
        "warnings": warnings,
    }
