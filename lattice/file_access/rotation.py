"""Conservative signed rollover for the dedicated Lattice file channel."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import tempfile

from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import (
    FileKeyError,
    fingerprint_ed25519_public_key,
    validate_ed25519_public_key,
)
from lattice.file_access.manifest import normalize_manifest, verify_manifest
from lattice.file_access.fleet_signing import sign_rotation_manifest
from lattice.file_access.sync import get_cached_signed_manifest
from lattice.file_access.keys import (
    DEFAULT_FILE_SSH_DIR,
    ensure_file_client_identity,
    ensure_file_host_identity,
)

ROTATION_DIR = Path("/var/lib/lattice/file-rotation")
PROPOSAL_PATH = ROTATION_DIR / "proposal.json"
PROMOTE_REQUEST_PATH = ROTATION_DIR / "promote.json"
PROMOTED_PATH = ROTATION_DIR / "promoted.json"
NEXT_CLIENT_NAME = "next_client_ed25519"
NEXT_HOST_NAME = "next_host_ed25519"
PREVIOUS_CLIENT_NAME = "previous_client_ed25519"
PREVIOUS_HOST_NAME = "previous_host_ed25519"


class FileRotationError(RuntimeError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _file_dir() -> Path:
    override = os.environ.get("LATTICE_FILE_SSH_DIR")
    return Path(override) if override else DEFAULT_FILE_SSH_DIR


def _rotation_dir() -> Path:
    override = os.environ.get("LATTICE_FILE_ROTATION_DIR")
    return Path(override) if override else ROTATION_DIR


def _proposal_path() -> Path:
    return _rotation_dir() / "proposal.json"


def _promote_request_path() -> Path:
    return _rotation_dir() / "promote.json"


def _promoted_path() -> Path:
    return _rotation_dir() / "promoted.json"


def _atomic_json(path: Path, payload: dict, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
    if os.geteuid() == 0 and path.parent == ROTATION_DIR:
        try:
            import grp
            lattice_gid = grp.getgrnam("lattice").gr_gid
            os.chown(path.parent, 0, lattice_gid)
            os.chmod(path.parent, 0o770)
        except KeyError:
            os.chmod(path.parent, 0o755)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), mode)
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise FileRotationError(f"Could not read rotation state {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FileRotationError(f"Rotation state {path} is invalid")
    return data


def _key_age_days(path: Path) -> float:
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError as exc:
        raise FileRotationError(f"Could not inspect file key age: {exc}") from exc
    return max(0.0, (_utc_now() - modified).total_seconds() / 86400.0)


def _ensure_next_pair(name: str, comment: str):
    from lattice.file_access.keys import _ensure_keypair
    return _ensure_keypair(_file_dir(), name, comment)


def ensure_rotation_staged_if_due() -> dict | None:
    """Root-side creation of a next keypair after the configured age."""
    if os.geteuid() != 0:
        return None
    identity = load_node_identity()
    if identity is None:
        return None
    config = load_config().file_access
    current_client = ensure_file_client_identity(_file_dir())
    current_host = ensure_file_host_identity(_file_dir())
    existing = _read_json(_proposal_path())
    if existing is not None:
        return existing
    if max(_key_age_days(current_client.private_key), _key_age_days(current_host.private_key)) < config.key_rotation_days:
        return None
    try:
        cached = get_cached_signed_manifest()
    except Exception:
        cached = None
    if cached is None:
        # Master nodes keep the same signed state in SQLite instead of cache.
        conn = get_db_connection()
        try:
            row = conn.execute("SELECT manifest FROM fleet_state WHERE id=1").fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        manifest = normalize_manifest(json.loads(row[0]))
    else:
        manifest = cached[0]
    local = next((m for m in manifest["members"] if m["node_id"] == identity.node_id), None)
    if local is None or not local.get("file_public_key"):
        return None
    next_generation = int(local["file_key_generation"]) + 1
    next_client = _ensure_next_pair(NEXT_CLIENT_NAME, "lattice-file-client-next")
    next_host = _ensure_next_pair(NEXT_HOST_NAME, "lattice-file-host-next")
    payload = {
        "node_id": identity.node_id,
        "current_generation": int(local["file_key_generation"]),
        "next_generation": next_generation,
        "next_public_key": next_client.public_key_text,
        "next_host_public_key": next_host.public_key_text,
        "next_host_key_fingerprint": next_host.fingerprint,
        "proposed_at": _utc_now().isoformat(),
    }
    _atomic_json(_proposal_path(), payload, mode=0o644)
    return payload


def get_local_rotation_proposal() -> dict | None:
    if _read_json(_promoted_path()) is not None:
        return None
    return _read_json(_proposal_path())


def record_promote_request(payload: object) -> bool:
    if not isinstance(payload, dict) or payload.get("action") != "promote":
        return False
    required = ("node_id", "next_generation", "overlap_generation")
    if any(key not in payload for key in required):
        raise FileRotationError("File promotion request is incomplete")
    _atomic_json(_promote_request_path(), {key: payload[key] for key in ("action", *required)}, mode=0o644)
    return True


def get_promoted_generation() -> int | None:
    # A promoted key is not reportable until the dedicated sshd has been
    # restarted successfully and the promotion request is cleared.
    if _read_json(_promote_request_path()) is not None:
        return None
    payload = _read_json(_promoted_path())
    if payload is None:
        return None
    value = payload.get("generation")
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def confirm_local_promotion_ready() -> bool:
    if _read_json(_promoted_path()) is None:
        return False
    _promote_request_path().unlink(missing_ok=True)
    return True



def _load_master_state(conn: sqlite3.Connection) -> tuple[sqlite3.Row, dict, object]:
    row = conn.execute(
        "SELECT fleet_id, generation, manifest, signature, signing_public_key FROM fleet_state WHERE id=1"
    ).fetchone()
    if row is None:
        raise FileRotationError("Master fleet state is unavailable")
    manifest = normalize_manifest(json.loads(row["manifest"]))
    signing_public_key = str(row["signing_public_key"])
    if not verify_manifest(manifest, row["signature"], signing_public_key):
        raise FileRotationError("Current fleet signature is invalid")
    return row, manifest, signing_public_key


def _validate_proposal(member: dict, proposal: object) -> dict:
    if not isinstance(proposal, dict):
        raise FileRotationError("File rotation proposal is invalid")
    if proposal.get("node_id") != member["node_id"]:
        raise FileRotationError("File rotation proposal has the wrong Node ID")
    current = proposal.get("current_generation")
    nxt = proposal.get("next_generation")
    if current != member.get("file_key_generation") or nxt != current + 1:
        raise FileRotationError("File rotation proposal has the wrong key generation")
    try:
        next_public = validate_ed25519_public_key(proposal["next_public_key"])
        next_host = validate_ed25519_public_key(proposal["next_host_public_key"])
    except (KeyError, FileKeyError) as exc:
        raise FileRotationError("File rotation proposal contains an invalid key") from exc
    fingerprint = proposal.get("next_host_key_fingerprint")
    if fingerprint != fingerprint_ed25519_public_key(next_host):
        raise FileRotationError("File rotation proposal host fingerprint is invalid")
    next_client_identity = next_public.split()[:2]
    next_host_identity = next_host.split()[:2]
    forbidden = [
        member["file_public_key"].split()[:2],
        member["file_host_public_key"].split()[:2],
    ]
    for field in ("shell_public_key", "shell_host_public_key"):
        if member.get(field):
            forbidden.append(member[field].split()[:2])
    if next_client_identity == next_host_identity:
        raise FileRotationError("File rotation client and host keys must be separate")
    if next_client_identity in forbidden or next_host_identity in forbidden:
        raise FileRotationError("File rotation must use entirely new SSH identities")
    return {
        "next_generation": nxt,
        "next_public_key": next_public,
        "next_host_public_key": next_host,
        "next_host_key_fingerprint": fingerprint,
    }


def process_master_rotation_proposal(target_node_id: str, proposal: object) -> dict[str, object]:
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        state, manifest, signing_public_key = _load_master_state(conn)
        member = next((m for m in manifest["members"] if m["node_id"] == target_node_id), None)
        if member is None or not member.get("file_public_key"):
            raise FileRotationError("Rotation target is not an active file-enabled fleet member")
        values = _validate_proposal(member, proposal)
        existing = conn.execute("SELECT * FROM file_key_rotations WHERE target_node_id=?", (target_node_id,)).fetchone()
        if existing is not None:
            same = (
                int(existing["next_generation"]) == values["next_generation"]
                and existing["next_public_key"] == values["next_public_key"]
                and existing["next_host_public_key"] == values["next_host_public_key"]
            )
            if not same:
                raise FileRotationError("A conflicting file rotation already exists for this node")
            conn.commit()
            return {"status": existing["stage"], "generation": existing["overlap_generation"]}
        other = conn.execute("SELECT target_node_id FROM file_key_rotations LIMIT 1").fetchone()
        if other is not None:
            conn.rollback()
            return {"status": "waiting_for_other_rotation"}
        if conn.execute("SELECT 1 FROM shell_key_rotations LIMIT 1").fetchone() is not None:
            conn.rollback()
            return {"status": "waiting_for_shell_rotation"}
        if conn.execute("SELECT 1 FROM fleet_pending_updates LIMIT 1").fetchone() is not None:
            conn.rollback()
            return {"status": "waiting_for_membership_update"}
        updated_members = []
        for item in manifest["members"]:
            copy = dict(item)
            if copy["node_id"] == target_node_id:
                copy.update({
                    "file_next_public_key": values["next_public_key"],
                    "file_next_host_public_key": values["next_host_public_key"],
                    "file_next_host_key_fingerprint": values["next_host_key_fingerprint"],
                    "file_next_key_generation": values["next_generation"],
                })
            updated_members.append(copy)
        overlap_generation = int(state["generation"]) + 1
        overlap = normalize_manifest({
            "schema_version": manifest["schema_version"],
            "fleet_id": manifest["fleet_id"],
            "generation": overlap_generation,
            "members": updated_members,
            "revoked": manifest["revoked"],
        })
        signature = sign_rotation_manifest(
            "file-overlap",
            target_node_id,
            overlap,
            signing_public_key,
        )
        if not verify_manifest(overlap, signature, signing_public_key):
            raise FileRotationError("File overlap generation failed self-verification")
        conn.execute(
            "UPDATE fleet_state SET generation=?, manifest=?, signature=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (
                overlap_generation,
                json.dumps(overlap, sort_keys=True, separators=(",", ":")),
                signature,
            ),
        )
        conn.execute(
            "UPDATE fleet_nodes SET membership_generation=?, updated_at=CURRENT_TIMESTAMP WHERE role='master' AND membership_state='active'",
            (overlap_generation,),
        )
        conn.execute(
            """INSERT INTO file_key_rotations (
                   target_node_id, next_generation, next_public_key,
                   next_host_public_key, next_host_key_fingerprint,
                   overlap_generation, stage
               ) VALUES (?, ?, ?, ?, ?, ?, 'overlap')""",
            (
                target_node_id,
                values["next_generation"],
                values["next_public_key"],
                values["next_host_public_key"],
                values["next_host_key_fingerprint"],
                overlap_generation,
            ),
        )
        conn.commit()
        return {"status": "overlap", "generation": overlap_generation}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def rotation_promotion_request_for(target_node_id: str) -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM file_key_rotations WHERE target_node_id=? AND stage IN ('overlap','promote_requested')",
            (target_node_id,),
        ).fetchone()
        if row is None or row["overlap_generation"] is None:
            return None
        lagging = conn.execute(
            """SELECT COUNT(*) FROM fleet_nodes
               WHERE membership_state='active' AND file_transport_generation < ?""",
            (int(row["overlap_generation"]),),
        ).fetchone()[0]
        if int(lagging) != 0:
            _ensure_stalled_alert(conn, row, int(lagging))
            conn.commit()
            return None
        conn.execute(
            "UPDATE file_key_rotations SET stage='promote_requested', updated_at=CURRENT_TIMESTAMP WHERE target_node_id=?",
            (target_node_id,),
        )
        conn.commit()
        return {
            "action": "promote",
            "node_id": target_node_id,
            "next_generation": int(row["next_generation"]),
            "overlap_generation": int(row["overlap_generation"]),
        }
    finally:
        conn.close()


def _current_manifest_for_local() -> dict:
    try:
        cached = get_cached_signed_manifest()
    except Exception:
        cached = None
    if cached is not None:
        return cached[0]
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT manifest FROM fleet_state WHERE id=1").fetchone()
    finally:
        conn.close()
    if row is None:
        raise FileRotationError("No signed fleet generation is available")
    return normalize_manifest(json.loads(row[0]))


def _public_text(path: Path) -> str:
    try:
        return validate_ed25519_public_key(path.read_text(encoding="utf-8").strip())
    except (OSError, FileKeyError) as exc:
        raise FileRotationError(f"Could not read file public key {path}: {exc}") from exc


def _replace_pair_if_needed(current_name: str, next_name: str, previous_name: str, expected_public: str) -> None:
    directory = _file_dir()
    current_private = directory / current_name
    current_public = directory / f"{current_name}.pub"
    next_private = directory / next_name
    next_public = directory / f"{next_name}.pub"
    previous_private = directory / previous_name
    previous_public = directory / f"{previous_name}.pub"
    if current_public.exists() and _public_text(current_public).split()[:2] == expected_public.split()[:2]:
        return
    if not next_private.is_file() or not next_public.is_file():
        raise FileRotationError(f"Staged file keypair {next_name} is missing")
    if _public_text(next_public).split()[:2] != expected_public.split()[:2]:
        raise FileRotationError(f"Staged file keypair {next_name} does not match signed promotion")
    if current_private.exists() and current_public.exists():
        shutil.copy2(current_private, previous_private)
        shutil.copy2(current_public, previous_public)
    os.replace(next_private, current_private)
    os.replace(next_public, current_public)


def promote_local_rotation_if_requested() -> int | None:
    if os.geteuid() != 0:
        return None
    request = _read_json(_promote_request_path())
    if request is None:
        return None
    identity = load_node_identity()
    if identity is None or request.get("node_id") != identity.node_id:
        raise FileRotationError("File promotion request targets the wrong computer")
    manifest = _current_manifest_for_local()
    if manifest["generation"] != request.get("overlap_generation"):
        raise FileRotationError("File promotion request does not match the current signed overlap generation")
    member = next((m for m in manifest["members"] if m["node_id"] == identity.node_id), None)
    if member is None or member.get("file_next_key_generation") != request.get("next_generation"):
        raise FileRotationError("Signed fleet state does not authorize this file promotion")
    _replace_pair_if_needed("client_ed25519", NEXT_CLIENT_NAME, PREVIOUS_CLIENT_NAME, member["file_next_public_key"])
    _replace_pair_if_needed("host_ed25519", NEXT_HOST_NAME, PREVIOUS_HOST_NAME, member["file_next_host_public_key"])
    _atomic_json(_promoted_path(), {"node_id": identity.node_id, "generation": int(request["next_generation"]), "promoted_at": _utc_now().isoformat()}, mode=0o644)
    # Keep the promotion request until the manager proves the dedicated sshd
    # restarted successfully on the new host key.
    return int(request["next_generation"])


def finalize_master_rotation(target_node_id: str, promoted_generation: int) -> dict[str, object]:
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        rotation = conn.execute(
            "SELECT * FROM file_key_rotations WHERE target_node_id=?",
            (target_node_id,),
        ).fetchone()
        if rotation is None:
            conn.rollback()
            return {"status": "none"}
        if rotation["stage"] != "promote_requested":
            raise FileRotationError("File rotation is not ready for finalization")
        if int(rotation["next_generation"]) != int(promoted_generation):
            raise FileRotationError("Promoted file generation does not match the pending rotation")
        state, manifest, signing_public_key = _load_master_state(conn)
        if int(state["generation"]) != int(rotation["overlap_generation"]):
            raise FileRotationError("Fleet changed during file key overlap")
        members = []
        found = False
        for item in manifest["members"]:
            member = dict(item)
            if member["node_id"] == target_node_id:
                found = True
                if member.get("file_next_key_generation") != int(rotation["next_generation"]):
                    raise FileRotationError("Signed overlap no longer matches the pending file rotation")
                member["file_public_key"] = member.pop("file_next_public_key")
                member["file_host_public_key"] = member.pop("file_next_host_public_key")
                member["file_host_key_fingerprint"] = member.pop("file_next_host_key_fingerprint")
                member["file_key_generation"] = member.pop("file_next_key_generation")
            members.append(member)
        if not found:
            raise FileRotationError("File rotation target disappeared from active membership")
        final_generation = int(state["generation"]) + 1
        final = normalize_manifest({
            "schema_version": manifest["schema_version"],
            "fleet_id": manifest["fleet_id"],
            "generation": final_generation,
            "members": members,
            "revoked": manifest["revoked"],
        })
        signature = sign_rotation_manifest(
            "file-finalize",
            target_node_id,
            final,
            signing_public_key,
        )
        if not verify_manifest(final, signature, signing_public_key):
            raise FileRotationError("Final file rotation generation failed self-verification")
        target = next(member for member in final["members"] if member["node_id"] == target_node_id)
        conn.execute(
            "UPDATE fleet_state SET generation=?, manifest=?, signature=?, updated_at=CURRENT_TIMESTAMP WHERE id=1",
            (final_generation, json.dumps(final, sort_keys=True, separators=(",", ":")), signature),
        )
        conn.execute(
            """UPDATE fleet_nodes SET file_public_key=?, file_key_generation=?,
               file_host_public_key=?, file_host_key_fingerprint=?, updated_at=CURRENT_TIMESTAMP
               WHERE node_id=? AND membership_state='active'""",
            (target["file_public_key"], target["file_key_generation"], target["file_host_public_key"], target["file_host_key_fingerprint"], target_node_id),
        )
        conn.execute(
            "UPDATE fleet_nodes SET membership_generation=?, updated_at=CURRENT_TIMESTAMP WHERE role='master' AND membership_state='active'",
            (final_generation,),
        )
        if rotation["alert_id"] is not None:
            now = _utc_now().isoformat()
            event = conn.execute(
                """INSERT INTO events (timestamp, worker_id, type, severity, message, details)
                   VALUES (?, (SELECT worker_id FROM fleet_nodes WHERE node_id=?),
                           'file_access.key_rotation_recovered', 'info', ?, ?)""",
                (now, target_node_id, "File key rotation completed after waiting for fleet acknowledgement.", json.dumps({"target_node_id": target_node_id}, sort_keys=True)),
            )
            conn.execute(
                "UPDATE alerts SET resolved_at=?, resolution_event_id=? WHERE id=? AND resolved_at IS NULL",
                (now, event.lastrowid, rotation["alert_id"]),
            )
        conn.execute("DELETE FROM file_key_rotations WHERE target_node_id=?", (target_node_id,))
        conn.commit()
        return {"status": "finalized", "generation": final_generation, "manifest": final, "signature": signature}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cleanup_completed_local_rotation() -> bool:
    if os.geteuid() != 0:
        return False
    proposal = _read_json(_proposal_path())
    if proposal is None:
        return False
    identity = load_node_identity()
    if identity is None or proposal.get("node_id") != identity.node_id:
        return False
    manifest = _current_manifest_for_local()
    local = next((m for m in manifest["members"] if m["node_id"] == identity.node_id), None)
    if local is None or local.get("file_next_public_key") is not None:
        return False
    if local.get("file_key_generation") != proposal.get("next_generation"):
        return False
    current_client = _public_text(_file_dir() / "client_ed25519.pub")
    current_host = _public_text(_file_dir() / "host_ed25519.pub")
    if current_client.split()[:2] != local["file_public_key"].split()[:2]:
        return False
    if current_host.split()[:2] != local["file_host_public_key"].split()[:2]:
        return False
    for name in (
        PREVIOUS_CLIENT_NAME,
        f"{PREVIOUS_CLIENT_NAME}.pub",
        PREVIOUS_HOST_NAME,
        f"{PREVIOUS_HOST_NAME}.pub",
    ):
        (_file_dir() / name).unlink(missing_ok=True)
    _proposal_path().unlink(missing_ok=True)
    _promoted_path().unlink(missing_ok=True)
    _promote_request_path().unlink(missing_ok=True)
    return True


ROTATION_STALL_ALERT_SECONDS = 24 * 60 * 60


def _parse_sqlite_time(value: object) -> datetime:
    text = str(value).strip().replace(" ", "T")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ensure_stalled_alert(conn: sqlite3.Connection, rotation, lagging: int) -> None:
    if rotation["alert_id"] is not None:
        return
    try:
        age = (_utc_now() - _parse_sqlite_time(rotation["proposed_at"])).total_seconds()
    except (ValueError, TypeError):
        age = ROTATION_STALL_ALERT_SECONDS
    if age < ROTATION_STALL_ALERT_SECONDS:
        return
    target = conn.execute(
        "SELECT worker_id, hostname FROM fleet_nodes WHERE node_id=?",
        (rotation["target_node_id"],),
    ).fetchone()
    worker_id = target["worker_id"] if target is not None else None
    hostname = target["hostname"] if target is not None else rotation["target_node_id"]
    now = _utc_now().isoformat()
    message = (
        f"File key rotation for {hostname} is waiting for {lagging} trusted "
        "computer(s) to acknowledge the signed overlap generation. Old keys remain valid. "
        "Lattice will keep retrying automatically. Keep waiting if the computer is only "
        "temporarily offline, bring it online to retry immediately, or securely revoke it "
        "from the Workers screen if it is permanently gone."
    )
    event = conn.execute(
        """INSERT INTO events (timestamp, worker_id, type, severity, message, details)
           VALUES (?, ?, 'file_access.key_rotation_stalled', 'warning', ?, ?)""",
        (now, worker_id, message, json.dumps({"target_node_id": rotation["target_node_id"], "lagging": lagging}, sort_keys=True)),
    )
    alert = conn.execute(
        """INSERT INTO alerts (worker_id, severity, title, message, trigger_event_id, fired_at)
           VALUES (?, 'warning', 'File key rotation waiting', ?, ?, ?)""",
        (worker_id, message, event.lastrowid, now),
    )
    conn.execute(
        "UPDATE file_key_rotations SET alert_id=?, updated_at=CURRENT_TIMESTAMP WHERE target_node_id=?",
        (alert.lastrowid, rotation["target_node_id"]),
    )
