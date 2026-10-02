"""Fail-closed validation for local backup targets."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
from typing import Callable

from lattice.backup.models import MountIdentity, validate_uuid4


class BackupTargetError(RuntimeError):
    pass


def inspect_mount(path: Path) -> MountIdentity:
    path = Path(path).resolve(strict=False)
    try:
        result = subprocess.run(
            ["findmnt", "--json", "--target", str(path), "--output", "TARGET,UUID,SOURCE,FSTYPE,OPTIONS"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        payload = json.loads(result.stdout)
        rows = payload.get("filesystems", [])
        if len(rows) != 1:
            raise BackupTargetError("Backup target mount identity is ambiguous")
        row = rows[0]
        fs_uuid = str(row.get("uuid") or "").strip()
        target = str(row.get("target") or "").strip()
        if not fs_uuid or not target:
            raise BackupTargetError("Backup target filesystem has no stable UUID or mountpoint")
        return MountIdentity(
            target=Path(target).resolve(strict=False),
            filesystem_uuid=fs_uuid,
            source=str(row.get("source") or ""),
            filesystem_type=str(row.get("fstype") or ""),
            options=frozenset(str(row.get("options") or "").split(",")),
        )
    except BackupTargetError:
        raise
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise BackupTargetError("Could not verify backup target mount identity") from exc


def validate_repository_target(
    repository_root: Path,
    filesystem_uuid: str,
    *,
    inspector: Callable[[Path], MountIdentity] = inspect_mount,
    require_writable: bool = True,
) -> MountIdentity:
    """Validate a repository by stable filesystem identity, not mountpoint."""
    repository_root = Path(repository_root).resolve(strict=False)
    if not repository_root.is_absolute():
        raise BackupTargetError("Backup repository path must be absolute")
    if not isinstance(filesystem_uuid, str) or not filesystem_uuid.strip():
        raise BackupTargetError("Backup target filesystem UUID is invalid")
    identity = inspector(repository_root)
    if identity.filesystem_uuid != filesystem_uuid.strip():
        raise BackupTargetError(
            "Backup target filesystem identity does not match the registered drive"
        )
    try:
        repository_root.relative_to(identity.target)
    except ValueError as exc:
        raise BackupTargetError(
            "Backup repository is outside the registered backup filesystem"
        ) from exc
    if "ro" in identity.options:
        raise BackupTargetError("Backup target filesystem is mounted read-only")
    probe = repository_root if repository_root.exists() else repository_root.parent
    if require_writable and probe.exists() and not os.access(probe, os.W_OK):
        raise BackupTargetError("Backup destination is not writable")
    return identity


@dataclass(frozen=True)
class LocalBackupTarget:
    target_id: str
    friendly_name: str
    filesystem_uuid: str
    mount_path: Path
    repository_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "target_id", validate_uuid4(self.target_id, "Backup target ID"))
        if not self.friendly_name.strip() or len(self.friendly_name) > 100:
            raise BackupTargetError("Backup target name is invalid")
        if not self.filesystem_uuid.strip() or len(self.filesystem_uuid) > 128:
            raise BackupTargetError("Backup target filesystem UUID is invalid")
        mount = Path(self.mount_path)
        repo = Path(self.repository_root)
        if not mount.is_absolute() or not repo.is_absolute():
            raise BackupTargetError("Backup target paths must be absolute")

    def validate(
        self, *, inspector: Callable[[Path], MountIdentity] = inspect_mount, require_writable: bool = True
    ) -> MountIdentity:
        mount_path = Path(self.mount_path).resolve(strict=False)
        repository_root = Path(self.repository_root).resolve(strict=False)
        identity = inspector(repository_root)
        if identity.filesystem_uuid != self.filesystem_uuid:
            raise BackupTargetError("Backup target filesystem identity does not match the registered drive")
        if identity.target != mount_path:
            raise BackupTargetError("Backup target is not mounted at its registered mountpoint")
        try:
            repository_root.relative_to(mount_path)
        except ValueError as exc:
            raise BackupTargetError("Backup repository is outside the registered backup filesystem") from exc
        if "ro" in identity.options:
            raise BackupTargetError("Backup target filesystem is mounted read-only")
        if require_writable and repository_root.exists() and not os.access(repository_root, os.W_OK):
            raise BackupTargetError("Backup destination is not writable")
        return identity


def inspect_uuid_mount(filesystem_uuid: str) -> MountIdentity:
    """Resolve one currently mounted filesystem by its stable UUID."""
    if not isinstance(filesystem_uuid, str) or not filesystem_uuid.strip():
        raise BackupTargetError("Backup target filesystem UUID is invalid")
    try:
        result = subprocess.run(
            [
                "findmnt", "--json", "--source", f"UUID={filesystem_uuid.strip()}",
                "--output", "TARGET,UUID,SOURCE,FSTYPE,OPTIONS",
            ],
            check=True, capture_output=True, text=True, timeout=5,
        )
        payload = json.loads(result.stdout)
        rows = payload.get("filesystems", [])
        physical_rows = [
            row for row in rows
            if "[" not in str(row.get("source") or "")
        ]
        if len(physical_rows) != 1:
            raise BackupTargetError("Registered backup drive is not mounted exactly once")
        row = physical_rows[0]
        actual_uuid = str(row.get("uuid") or "").strip()
        target = str(row.get("target") or "").strip()
        if actual_uuid != filesystem_uuid.strip() or not target:
            raise BackupTargetError("Registered backup drive identity could not be confirmed")
        return MountIdentity(
            target=Path(target).resolve(strict=False),
            filesystem_uuid=actual_uuid,
            source=str(row.get("source") or ""),
            filesystem_type=str(row.get("fstype") or ""),
            options=frozenset(str(row.get("options") or "").split(",")),
        )
    except BackupTargetError:
        raise
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError) as exc:
        raise BackupTargetError("Could not locate the registered backup drive") from exc


def resolve_repository_root(
    filesystem_uuid: str,
    repository_relative_path: str,
    *,
    inspector: Callable[[str], MountIdentity] = inspect_uuid_mount,
    require_writable: bool = True,
) -> tuple[Path, MountIdentity]:
    """Resolve a repository from stable drive UUID + safe relative path."""
    if not isinstance(repository_relative_path, str) or not repository_relative_path.strip():
        raise BackupTargetError("Backup repository relative path is invalid")
    relative = Path(repository_relative_path)
    if relative.is_absolute() or ".." in relative.parts or "\x00" in repository_relative_path:
        raise BackupTargetError("Backup repository relative path is unsafe")
    identity = inspector(filesystem_uuid)
    if identity.filesystem_uuid != filesystem_uuid.strip():
        raise BackupTargetError("Backup target filesystem identity does not match the registered drive")
    if "ro" in identity.options:
        raise BackupTargetError("Backup target filesystem is mounted read-only")
    repository = (identity.target / relative).resolve(strict=False)
    try:
        repository.relative_to(identity.target)
    except ValueError as exc:
        raise BackupTargetError("Backup repository escaped the registered backup filesystem") from exc
    probe = repository if repository.exists() else identity.target
    if require_writable and not os.access(probe, os.W_OK):
        raise BackupTargetError("Backup destination is not writable")
    return repository, identity
