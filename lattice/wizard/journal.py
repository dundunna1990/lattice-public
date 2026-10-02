import json
import logging
import os
import stat
import tempfile

logger = logging.getLogger(__name__)
from pathlib import Path


JOURNAL_PATH = Path(
    os.environ.get("LATTICE_WIZARD_JOURNAL_PATH", "/var/lib/lattice-root/wizard-journal.json")
)
JOURNAL_VERSION = 2


def _ensure_secure_parent() -> None:
    """Refuse to write root wizard state below a daemon-writable directory."""
    parent = JOURNAL_PATH.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    details = parent.stat()
    if details.st_uid != 0 or details.st_mode & 0o077:
        raise PermissionError(f"Wizard journal directory is not root-private: {parent}")


def _read_secure_json(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
        details = os.fstat(handle.fileno())
        if not stat.S_ISREG(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o077:
            raise PermissionError(f"Wizard journal is not a private root-owned file: {path}")
        return json.load(handle)


def load_journal():
    if not JOURNAL_PATH.exists():
        return None
    payload = _read_secure_json(JOURNAL_PATH)
    if not isinstance(payload, dict) or payload.get("version") != JOURNAL_VERSION:
        logger.warning("Ignoring an incompatible Lattice setup journal")
        return None
    return payload


def save_journal(step, data):
    _ensure_secure_parent()
    descriptor, temporary_name = tempfile.mkstemp(
        dir=JOURNAL_PATH.parent, prefix=f".{JOURNAL_PATH.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump({"version": JOURNAL_VERSION, "step": step, "data": data}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, JOURNAL_PATH)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def clear_journal():
    if JOURNAL_PATH.exists():
        _read_secure_json(JOURNAL_PATH)
        JOURNAL_PATH.unlink()
