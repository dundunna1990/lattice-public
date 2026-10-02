"""Queue signed backup assignment state for root-side transport reconciliation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

from lattice.backup.assignment import (
    BackupAssignmentError,
    canonical_assignment_bytes,
    normalize_assignment,
)

DEFAULT_REQUEST_PATH = Path("/var/lib/lattice/backup-transport-request.json")


class BackupTransportQueueError(RuntimeError):
    pass


def _request_path() -> Path:
    override = os.environ.get("LATTICE_BACKUP_TRANSPORT_REQUEST_PATH")
    return Path(override) if override else DEFAULT_REQUEST_PATH


def _read_existing(path: Path) -> dict | None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BackupTransportQueueError(f"Could not safely open existing request: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise BackupTransportQueueError("Existing backup transport request is unsafe")
        if metadata.st_mode & 0o022:
            raise BackupTransportQueueError("Existing backup transport request permissions are unsafe")
        if metadata.st_size > 524288:
            raise BackupTransportQueueError("Existing backup transport request is too large")
        raw = os.read(descriptor, 524289)
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackupTransportQueueError("Existing backup transport request is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise BackupTransportQueueError("Existing backup transport request is invalid")
    return payload


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
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


def queue_backup_transport_reconcile(assignment_payload: object, signature: str) -> bool:
    """Queue a newer signed assignment generation; reject same-generation conflicts."""
    try:
        assignment = normalize_assignment(assignment_payload)
    except BackupAssignmentError as exc:
        raise BackupTransportQueueError(f"Backup assignment is invalid: {exc}") from exc
    if (
        not isinstance(signature, str)
        or "BEGIN SSH SIGNATURE" not in signature
        or "END SSH SIGNATURE" not in signature
    ):
        raise BackupTransportQueueError("Backup assignment signature is invalid")
    path = _request_path()
    existing = _read_existing(path)
    if existing is not None:
        try:
            old_assignment = normalize_assignment(existing["assignment"])
            old_signature = str(existing["signature"])
        except (KeyError, BackupAssignmentError) as exc:
            raise BackupTransportQueueError(
                "Existing backup transport request cannot be trusted"
            ) from exc
        old_generation = int(old_assignment["generation"])
        new_generation = int(assignment["generation"])
        if old_generation > new_generation:
            return False
        if old_generation == new_generation:
            if (
                canonical_assignment_bytes(old_assignment)
                == canonical_assignment_bytes(assignment)
                and old_signature == signature
            ):
                return False
            raise BackupTransportQueueError(
                "Conflicting backup transport state exists for the same generation"
            )
    _atomic_write(path, {"assignment": assignment, "signature": signature})
    return True
