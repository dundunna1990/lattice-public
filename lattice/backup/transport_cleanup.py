"""Prune stale Lattice-owned Backup transport resources after SSH revocation."""
from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path

from lattice.backup.transport import (
    _ACCOUNT_RE,
    DEFAULT_AUTHORIZED_KEYS_DIR,
    DEFAULT_CHROOT_ROOT,
)
from lattice.backup.transport_apply import _run, _safe_json
from lattice.file_access.home_export import FileHomeExportError, exact_mount_source

DESIRED_STATE_PATH = Path("/var/lib/lattice/backup-transport-desired.json")


class BackupTransportCleanupError(RuntimeError):
    pass


def _managed_names(path: Path, *, directories: bool) -> set[str]:
    if not path.exists():
        return set()
    if path.is_symlink() or not path.is_dir():
        raise BackupTransportCleanupError(f"Managed Backup path is unsafe: {path}")
    result: set[str] = set()
    for child in path.iterdir():
        if not _ACCOUNT_RE.fullmatch(child.name):
            continue
        metadata = child.lstat()
        if directories:
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise BackupTransportCleanupError(f"Managed Backup chroot is unsafe: {child}")
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BackupTransportCleanupError(
                f"Managed Backup authorized-key path is unsafe: {child}"
            )
        result.add(child.name)
    return result


def _desired_accounts(path: Path = DESIRED_STATE_PATH) -> set[str]:
    payload = _safe_json(path, allowed_uids={0}, maximum=65536)
    if payload.get("schema_version") != 1:
        raise BackupTransportCleanupError("Backup transport desired-state schema is invalid")
    accounts = payload.get("accounts")
    if not isinstance(accounts, list) or len(accounts) > 256:
        raise BackupTransportCleanupError("Backup transport desired accounts are invalid")
    result: set[str] = set()
    for value in accounts:
        if not isinstance(value, str) or not _ACCOUNT_RE.fullmatch(value) or value in result:
            raise BackupTransportCleanupError(
                "Backup transport desired account is invalid or duplicated"
            )
        result.add(value)
    return result


def _remove_authorized_key(username: str) -> None:
    path = DEFAULT_AUTHORIZED_KEYS_DIR / username
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BackupTransportCleanupError(f"Refusing to remove unsafe Backup key path: {path}")
    path.unlink()


def _remove_chroot(username: str, *, runner=_run) -> None:
    chroot = DEFAULT_CHROOT_ROOT / username
    if not chroot.exists() and not chroot.is_symlink():
        return
    metadata = chroot.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise BackupTransportCleanupError(f"Refusing to remove unsafe Backup chroot: {chroot}")
    target = chroot / "repo"
    try:
        mounted = exact_mount_source(target)
    except FileHomeExportError as exc:
        raise BackupTransportCleanupError(str(exc)) from exc
    if mounted is not None:
        runner(["/usr/bin/umount", str(target)])
        try:
            if exact_mount_source(target) is not None:
                raise BackupTransportCleanupError(f"Stale Backup bind remained mounted: {target}")
        except FileHomeExportError as exc:
            raise BackupTransportCleanupError(str(exc)) from exc
    if target.exists() or target.is_symlink():
        target_meta = target.lstat()
        if not stat.S_ISDIR(target_meta.st_mode) or stat.S_ISLNK(target_meta.st_mode):
            raise BackupTransportCleanupError(
                f"Refusing to remove unsafe Backup repo target: {target}"
            )
        try:
            target.rmdir()
        except OSError as exc:
            raise BackupTransportCleanupError(
                f"Stale Backup repo target is not empty: {target}"
            ) from exc
    try:
        chroot.rmdir()
    except OSError as exc:
        raise BackupTransportCleanupError(f"Stale Backup chroot is not empty: {chroot}") from exc


def _remove_account(username: str, *, runner=_run) -> None:
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        account = None
    if account is not None:
        if account.pw_uid == 0 or account.pw_dir != "/" or account.pw_shell not in {
            "/usr/sbin/nologin", "/bin/false",
        }:
            raise BackupTransportCleanupError(f"Refusing to remove unexpected account {username}")
        runner(["/usr/sbin/userdel", username])
    try:
        group = grp.getgrnam(username)
    except KeyError:
        return
    if group.gr_mem:
        raise BackupTransportCleanupError(f"Refusing to remove non-empty Backup group {username}")
    runner(["/usr/sbin/groupdel", username])


def cleanup_stale_transport(
    desired_state_path: Path = DESIRED_STATE_PATH,
    *,
    runner=_run,
) -> int:
    if os.geteuid() != 0:
        raise BackupTransportCleanupError("Backup transport cleanup must run as root")
    desired = _desired_accounts(desired_state_path)
    existing = _managed_names(DEFAULT_CHROOT_ROOT, directories=True)
    existing |= _managed_names(DEFAULT_AUTHORIZED_KEYS_DIR, directories=False)
    existing |= {
        item.pw_name for item in pwd.getpwall()
        if _ACCOUNT_RE.fullmatch(item.pw_name)
    }
    removed = 0
    for username in sorted(existing - desired):
        _remove_authorized_key(username)
        _remove_chroot(username, runner=runner)
        _remove_account(username, runner=runner)
        removed += 1
    return removed


def main() -> None:
    try:
        removed = cleanup_stale_transport()
    except BackupTransportCleanupError as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1) from exc
    print(f"Pruned {removed} stale Lattice Backup transport account(s)")


if __name__ == "__main__":
    main()
