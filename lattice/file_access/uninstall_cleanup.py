"""Fail-closed cleanup of Lattice-owned mounts before uninstall/purge."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess

from lattice.file_access.mount_manager import (
    FUSERMOUNT_BINARY,
    MountManagerError,
    find_mount_entry,
    is_lattice_sshfs_mount,
)
from lattice.file_access.transport_apply import HOME_TARGET, LEGACY_HOME_TARGET, _exact_mount_source

MOUNT_ROOT = Path('/mnt/lattice')
MAX_HOME_UNMOUNT_LAYERS = 16
BACKUP_CHROOT_ROOT = Path('/srv/lattice-backup-chroot')
_BACKUP_ACCOUNT_RE = re.compile(r'^lattice-bkp-[0-9a-f]{20}$')
MAX_BACKUP_UNMOUNT_LAYERS = 8

class UninstallCleanupError(RuntimeError):
    pass


def _run(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or 'unmount failed').strip()
        raise UninstallCleanupError(f"{' '.join(command)}: {detail}")


def _mountinfo() -> str:
    try:
        return Path('/proc/self/mountinfo').read_text(encoding='utf-8')
    except OSError as exc:
        raise UninstallCleanupError(f'Could not inspect mount table: {exc}') from exc


def detach_peer_mounts() -> int:
    text = _mountinfo()
    if not MOUNT_ROOT.exists():
        return 0
    count = 0
    for child in MOUNT_ROOT.iterdir():
        if child.is_symlink() or not child.is_dir():
            continue
        entry = find_mount_entry(child, text)
        if entry is None:
            continue
        if not is_lattice_sshfs_mount(child, entry, mount_root=MOUNT_ROOT):
            raise UninstallCleanupError(f'Refusing to detach non-Lattice mount at {child}')
        _run([FUSERMOUNT_BINARY, '-u', str(child)])
        count += 1
        text = _mountinfo()
        if find_mount_entry(child, text) is not None:
            raise UninstallCleanupError(f'Lattice peer mount remained attached at {child}')
    return count


def detach_home_bind() -> bool:
    detached = False

    for target in (HOME_TARGET, LEGACY_HOME_TARGET):
        layers = 0

        while _exact_mount_source(target) is not None:
            if layers >= MAX_HOME_UNMOUNT_LAYERS:
                raise UninstallCleanupError(
                    f'Lattice Home target still has mounts after '
                    f'{MAX_HOME_UNMOUNT_LAYERS} detach attempts: {target}'
                )

            try:
                _run(['/usr/bin/umount', str(target)])
            except UninstallCleanupError as exc:
                # A logged-in desktop can legitimately keep an exported
                # Home layer busy. The target is Lattice's dedicated export
                # path, so detach that layer lazily and continue draining
                # any stacked layers beneath it.
                if 'busy' not in str(exc).lower():
                    raise
                _run(['/usr/bin/umount', '-l', str(target)])

            layers += 1

        if layers:
            detached = True

    return detached


def detach_backup_binds() -> int:
    if not BACKUP_CHROOT_ROOT.exists():
        return 0
    count = 0
    for child in BACKUP_CHROOT_ROOT.iterdir():
        if child.is_symlink() or not child.is_dir() or not _BACKUP_ACCOUNT_RE.fullmatch(child.name):
            continue
        target = child / "repo"
        layers = 0
        while _exact_mount_source(target) is not None:
            if layers >= MAX_BACKUP_UNMOUNT_LAYERS:
                raise UninstallCleanupError(
                    f"Lattice backup target still has mounts after {MAX_BACKUP_UNMOUNT_LAYERS} detach attempts: {target}"
                )
            _run(['/usr/bin/umount', str(target)])
            layers += 1
            count += 1
    return count


def cleanup_lattice_mounts() -> dict[str, object]:
    peers = detach_peer_mounts()
    home = detach_home_bind()
    backups = detach_backup_binds()
    return {'peer_mounts': peers, 'home_bind': home, 'backup_binds': backups}


def main() -> None:
    try:
        result = cleanup_lattice_mounts()
    except (UninstallCleanupError, MountManagerError) as exc:
        print(f'ERROR: {exc}', file=__import__('sys').stderr)
        raise SystemExit(1)
    print(f"Detached {result['peer_mounts']} peer mount(s); Home bind detached={result['home_bind']}; backup bind(s)={result['backup_binds']}")

if __name__ == '__main__':
    main()
