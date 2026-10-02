"""Fleet reporting for local SSHFS mount state."""
from __future__ import annotations

from datetime import datetime, timezone

from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity

_ALLOWED_STATES = {
    "unknown", "discovering", "connecting", "mounted", "offline",
    "stale", "mount_problem", "reconnecting", "paused",
}


class MountObservationError(ValueError):
    pass


def local_mount_observations() -> list[dict]:
    identity = load_node_identity()
    if identity is None:
        return []
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT peer_node_id, state, error_code, updated_at
               FROM mount_state ORDER BY peer_node_id LIMIT 32"""
        ).fetchall()
        return [
            {
                "observer_node_id": identity.node_id,
                "peer_node_id": str(row["peer_node_id"]),
                "state": str(row["state"]),
                "error_code": row["error_code"],
                "last_changed_at": row["updated_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()

def normalize_mount_observations(payload: object, observer_node_id: str) -> list[dict]:
    if payload is None:
        return []
    if not isinstance(payload, list) or len(payload) > 32:
        raise MountObservationError("Mount observations must be a bounded list")
    result: list[dict] = []
    seen: set[str] = set()
    for raw in payload:
        if not isinstance(raw, dict):
            raise MountObservationError("Mount observation must be an object")
        if raw.get("observer_node_id") != observer_node_id:
            raise MountObservationError("Mount observation has the wrong observer Node ID")
        peer = raw.get("peer_node_id")
        state = raw.get("state")
        if not isinstance(peer, str) or not peer or peer in seen:
            raise MountObservationError("Mount observation peer is invalid or duplicated")
        if state not in _ALLOWED_STATES:
            raise MountObservationError("Mount observation state is invalid")
        error_code = raw.get("error_code")
        if error_code is not None and (not isinstance(error_code, str) or len(error_code) > 128):
            raise MountObservationError("Mount observation error code is invalid")
        changed = raw.get("last_changed_at")
        if changed is not None and (not isinstance(changed, str) or len(changed) > 80):
            raise MountObservationError("Mount observation timestamp is invalid")
        seen.add(peer)
        result.append({
            "observer_node_id": observer_node_id,
            "peer_node_id": peer,
            "state": state,
            "error_code": error_code,
            "last_changed_at": changed,
        })
    return result


def store_mount_observations(conn, observer_node_id: str, payload: object) -> int:
    observations = normalize_mount_observations(payload, observer_node_id)
    active_ids = {
        str(row["node_id"])
        for row in conn.execute(
            "SELECT node_id FROM fleet_nodes WHERE membership_state='active'"
        ).fetchall()
    }
    if observer_node_id not in active_ids:
        raise MountObservationError("Observer is not an active fleet member")
    now = datetime.now(timezone.utc).isoformat()
    stored = 0
    for item in observations:
        if item["peer_node_id"] not in active_ids or item["peer_node_id"] == observer_node_id:
            continue
        conn.execute(
            """INSERT INTO mount_observations
               (observer_node_id, peer_node_id, state, last_changed_at, last_reported_at, error_code)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(observer_node_id, peer_node_id) DO UPDATE SET
                 state=excluded.state, last_changed_at=excluded.last_changed_at,
                 last_reported_at=excluded.last_reported_at, error_code=excluded.error_code""",
            (observer_node_id, item["peer_node_id"], item["state"],
             item["last_changed_at"], now, item["error_code"]),
        )
        stored += 1
    return stored

def persist_local_mount_observations() -> int:
    identity = load_node_identity()
    if identity is None:
        return 0
    payload = local_mount_observations()
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        local = conn.execute(
            "SELECT membership_state FROM fleet_nodes WHERE node_id=?",
            (identity.node_id,),
        ).fetchone()
        if local is None or local["membership_state"] != "active":
            conn.rollback()
            return 0
        count = store_mount_observations(conn, identity.node_id, payload)
        conn.commit()
        return count
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
