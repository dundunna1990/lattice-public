"""Small immutable domain models for Lattice backups."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import uuid


class BackupModelError(ValueError):
    pass


def validate_uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupModelError(f"{label} is invalid") from exc
    if parsed.version != 4:
        raise BackupModelError(f"{label} must be UUIDv4")
    return str(parsed)


@dataclass(frozen=True)
class BackupSnapshot:
    snapshot_id: str
    time: str
    hostname: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class BackupSnapshotStats:
    total_size: int
    total_file_count: int


@dataclass(frozen=True)
class BackupEntry:
    path: str
    name: str
    entry_type: str
    size: int
    modified_at: str | None


@dataclass(frozen=True)
class MountIdentity:
    target: Path
    filesystem_uuid: str
    source: str
    filesystem_type: str
    options: frozenset[str]
