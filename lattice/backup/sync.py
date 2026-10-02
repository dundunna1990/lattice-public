"""Verify, cache, and queue master-signed backup assignment generations."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

from lattice.backup.keys import ensure_backup_host_identity
from lattice.backup.transport import DEFAULT_CHROOT_ROOT
from lattice.backup.transport_plan import build_local_transport_plan
from lattice.backup.targets import resolve_repository_root
from lattice.file_access.home_export import exact_mount_source

from lattice.backup.assignment import (
    BackupAssignmentError,
    canonical_assignment_bytes,
    normalize_assignment,
    verify_assignment,
)
from lattice.backup.transport_queue import queue_backup_transport_reconcile
from lattice.file_access.applied_state import BACKUP_APPLIED_PATH, applied_generation
from lattice.file_access.identity import load_node_identity
from lattice.file_access.sync import load_pinned_fleet_bootstrap

DEFAULT_CACHE_PATH = Path("/var/lib/lattice/backup-assignment.json")


class BackupSyncError(RuntimeError):
    pass


def _cache_path() -> Path:
    override = os.environ.get("LATTICE_BACKUP_ASSIGNMENT_CACHE")
    return Path(override) if override else DEFAULT_CACHE_PATH


def _read_cache(path: Path) -> dict | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BackupSyncError(f"Could not inspect cached backup assignment: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BackupSyncError("Cached backup assignment path is unsafe")
    if metadata.st_mode & 0o022 or metadata.st_size > 524288:
        raise BackupSyncError("Cached backup assignment permissions or size are unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupSyncError(f"Cached backup assignment is invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise BackupSyncError("Cached backup assignment must be an object")
    return payload


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _verify(payload: object, signature: str) -> dict:
    bootstrap = load_pinned_fleet_bootstrap()
    try:
        assignment = normalize_assignment(payload)
    except BackupAssignmentError as exc:
        raise BackupSyncError(f"Backup assignment is invalid: {exc}") from exc
    if assignment["fleet_id"] != bootstrap["fleet_id"]:
        raise BackupSyncError("Backup assignment belongs to a different fleet")
    try:
        valid = verify_assignment(
            assignment, signature, bootstrap["fleet_signing_public_key"]
        )
    except BackupAssignmentError as exc:
        raise BackupSyncError(str(exc)) from exc
    if not valid:
        raise BackupSyncError("Backup assignment signature is invalid")
    return assignment


def apply_signed_backup_assignment(payload: object, signature: str) -> dict:
    assignment = _verify(payload, signature)
    path = _cache_path()
    existing = _read_cache(path)
    if existing is not None:
        try:
            current = _verify(existing["assignment"], str(existing["signature"]))
        except (KeyError, BackupSyncError) as exc:
            raise BackupSyncError("Cached backup assignment cannot be trusted") from exc
        if current["generation"] > assignment["generation"]:
            raise BackupSyncError("Backup assignment would roll back trusted state")
        if current["generation"] == assignment["generation"]:
            if (
                canonical_assignment_bytes(current) != canonical_assignment_bytes(assignment)
                or str(existing["signature"]) != signature
            ):
                raise BackupSyncError("Conflicting backup assignment exists for this generation")
            ensure_backup_transport_current(assignment=assignment, signature=signature)
            return {"generation": assignment["generation"], "status": "current"}
    _atomic_write(path, {"assignment": assignment, "signature": signature})
    ensure_backup_transport_current(assignment=assignment, signature=signature)
    return {"generation": assignment["generation"], "status": "applied"}


def get_cached_signed_backup_assignment() -> tuple[dict, str] | None:
    existing = _read_cache(_cache_path())
    if existing is None:
        return None
    try:
        assignment = _verify(existing["assignment"], str(existing["signature"]))
    except (KeyError, BackupSyncError) as exc:
        raise BackupSyncError("Cached backup assignment cannot be trusted") from exc
    return assignment, str(existing["signature"])


def _backup_transport_health(
    assignment: dict,
    signature: str,
    identity,
    *,
    signing_public_key: str | None = None,
) -> str:
    """Return current, repairable, or unsafe for the local backup transport."""
    local_items = [
        item for item in assignment["assignments"]
        if item["target_node_id"] == identity.node_id
    ]
    if not local_items:
        return "current"

    try:
        if signing_public_key is None:
            bootstrap = load_pinned_fleet_bootstrap()
            signing_public_key = bootstrap["fleet_signing_public_key"]
        host_identity = ensure_backup_host_identity()
        plan = build_local_transport_plan(
            assignment,
            signature,
            signing_public_key,
            local_node_id=identity.node_id,
            local_host_public_key=host_identity.public_key_text,
            target_resolver=lambda filesystem_uuid, relative_path: resolve_repository_root(
                filesystem_uuid,
                relative_path,
                require_writable=False,
            ),
        )
    except Exception:
        return "unsafe"

    if len(plan) != len(local_items):
        return "unsafe"

    repairable = False
    for item in plan:
        source = item.repository_path
        try:
            metadata = source.lstat()
        except OSError:
            return "unsafe"
        if not stat.S_ISDIR(metadata.st_mode) or source.is_symlink():
            return "unsafe"

        target = DEFAULT_CHROOT_ROOT / item.username / "repo"
        try:
            mounted = exact_mount_source(target)
        except Exception:
            return "unsafe"
        if mounted is None:
            repairable = True
            continue
        try:
            source_stat = source.stat()
            target_stat = target.stat()
        except OSError:
            return "unsafe"
        if (
            source_stat.st_dev != target_stat.st_dev
            or source_stat.st_ino != target_stat.st_ino
        ):
            return "unsafe"

    return "repairable" if repairable else "current"


def ensure_backup_transport_current(
    *,
    assignment: dict | None = None,
    signature: str | None = None,
    signing_public_key: str | None = None,
) -> bool:
    identity = load_node_identity()
    if identity is None:
        return False
    if assignment is None or signature is None:
        cached = get_cached_signed_backup_assignment()
        if cached is None:
            return False
        assignment, signature = cached
    generation = int(assignment["generation"])
    current = applied_generation(BACKUP_APPLIED_PATH, identity.node_id)
    if current > generation:
        return False
    if current == generation:
        if signing_public_key is None:
            health = _backup_transport_health(assignment, signature, identity)
        else:
            health = _backup_transport_health(
                assignment,
                signature,
                identity,
                signing_public_key=signing_public_key,
            )
        if health == "current":
            return False
        if health == "unsafe":
            raise BackupSyncError(
                "Backup transport state is unsafe; refusing automatic recovery"
            )
    queue_backup_transport_reconcile(assignment, signature)
    return True
