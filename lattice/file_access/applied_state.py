"""Root-written acknowledgements that a signed transport generation is applied."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

FILE_SSHD_CONFIG_PATH = Path("/etc/lattice/file-ssh/sshd_config")

FILE_APPLIED_PATH = Path("/var/lib/lattice/file-transport-applied.json")
SHELL_APPLIED_PATH = Path("/var/lib/lattice/shell-transport-applied.json")
BACKUP_APPLIED_PATH = Path("/var/lib/lattice/backup-transport-applied.json")


class AppliedStateError(RuntimeError):
    pass


def write_applied_state(path: Path, *, node_id: str, generation: int) -> None:
    if os.geteuid() != 0:
        raise AppliedStateError("Applied transport state must be written by root")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise AppliedStateError("Applied transport generation is invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o640)
            json.dump({"node_id": node_id, "generation": generation}, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            import grp
            gid = grp.getgrnam("lattice").gr_gid
        except KeyError:
            gid = 0
        os.chown(temporary, 0, gid)
        os.replace(temporary, path)
        os.chmod(path, 0o640)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def read_applied_state(path: Path) -> dict | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise AppliedStateError("Applied transport state path is unsafe")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise AppliedStateError("Applied transport state permissions are unsafe")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AppliedStateError(f"Applied transport state is invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise AppliedStateError("Applied transport state must be an object")
    generation = payload.get("generation")
    node_id = payload.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        raise AppliedStateError("Applied transport Node ID is invalid")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise AppliedStateError("Applied transport generation is invalid")
    return {"node_id": node_id, "generation": generation}

def applied_generation(path: Path, expected_node_id: str) -> int:
    state = read_applied_state(path)
    if state is None or state["node_id"] != expected_node_id:
        return 0
    return int(state["generation"])

def record_applied_generation_in_db(channel: str, node_id: str, generation: int) -> bool:
    if channel not in {"file", "shell"}:
        raise AppliedStateError("Applied transport channel is invalid")
    from lattice.core.db import get_db_connection
    column = "file_transport_generation" if channel == "file" else "shell_transport_generation"
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            f"""UPDATE fleet_nodes SET {column}=MAX({column}, ?), updated_at=CURRENT_TIMESTAMP
                WHERE node_id=? AND membership_state='active'""",
            (generation, node_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()

def file_transport_config_is_current(identity, *, path: Path = FILE_SSHD_CONFIG_PATH) -> bool:
    """Return whether generated file-sshd policy matches the current code."""
    from lattice.file_access.transport import render_sshd_config

    try:
        metadata = path.lstat()
    except OSError:
        return False

    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        return False

    try:
        actual = path.read_text(encoding="utf-8")
        expected = render_sshd_config(main_user=identity.main_user)
    except (OSError, ValueError):
        return False

    return actual == expected


def ensure_file_transport_current() -> bool:
    """Queue signed file policy when generation or generated policy is stale."""
    from lattice.file_access.identity import load_node_identity
    from lattice.file_access.sync import get_cached_signed_manifest
    from lattice.file_access.transport_queue import queue_transport_reconcile
    identity = load_node_identity()
    if identity is None:
        return False
    try:
        cached = get_cached_signed_manifest()
    except Exception:
        cached = None
    if cached is not None:
        manifest, signature = cached
    else:
        from lattice.core.db import get_db_connection
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT manifest, signature FROM fleet_state WHERE id=1"
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return False
        import json
        from lattice.file_access.manifest import normalize_manifest
        manifest = normalize_manifest(json.loads(row["manifest"]))
        signature = str(row["signature"])
    generation = int(manifest["generation"])
    current = applied_generation(FILE_APPLIED_PATH, identity.node_id)
    if current > generation:
        record_applied_generation_in_db("file", identity.node_id, current)
        return False
    if current == generation:
        record_applied_generation_in_db("file", identity.node_id, current)
        from lattice.file_access.home_export import home_bind_is_current
        if (
            file_transport_config_is_current(identity)
            and home_bind_is_current(identity)
        ):
            return False
    queue_transport_reconcile(manifest, signature)
    return True
