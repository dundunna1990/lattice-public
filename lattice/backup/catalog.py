"""Read models used by backup setup and selection workflows."""
from __future__ import annotations

from lattice.core.db import get_db_connection


def backup_source_computers() -> list[dict]:
    """Return active fleet computers eligible to own backup jobs."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT node_id, hostname, role, main_user
               FROM fleet_nodes
               WHERE membership_state='active'
               ORDER BY CASE role WHEN 'master' THEN 0 ELSE 1 END, hostname COLLATE NOCASE"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def registered_backup_targets() -> list[dict]:
    """Return registered targets with their host computer names."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bt.id, bt.target_uuid, bt.friendly_name, bt.host_node_id,
                      fn.hostname AS host_hostname, bt.target_type, bt.filesystem_uuid,
                      bt.repository_root, bt.enabled
               FROM backup_targets AS bt
               JOIN fleet_nodes AS fn ON fn.node_id=bt.host_node_id
               ORDER BY bt.friendly_name COLLATE NOCASE"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _candidate_id(node_id: str, filesystem_uuid: str) -> str:
    import hashlib
    return hashlib.sha256(
        f"{node_id}:{filesystem_uuid}".encode("utf-8")
    ).hexdigest()[:20]


def fleet_storage_candidates(*, include_sensitive: bool = False) -> list[dict]:
    """Return current mounted storage candidates across the fleet.

    Normal operator callers get only opaque IDs and friendly metadata. The
    registration domain path may request the sensitive filesystem identity and
    mountpoint after the operator has selected an opaque candidate.
    """
    from lattice.backup.discovery import discover_storage
    from lattice.file_access.identity import load_node_identity

    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT bsc.observer_node_id, fn.hostname AS host_hostname,
                      bsc.filesystem_uuid, bsc.name, bsc.device,
                      bsc.filesystem_type, bsc.mountpoint, bsc.size_bytes,
                      bsc.removable, bsc.last_reported_at,
                      bt.id AS registered_target_id,
                      bt.friendly_name AS registered_target_name
               FROM backup_storage_candidates bsc
               JOIN fleet_nodes fn ON fn.node_id=bsc.observer_node_id
               LEFT JOIN backup_targets bt
                 ON bt.host_node_id=bsc.observer_node_id
                AND bt.filesystem_uuid=bsc.filesystem_uuid
                AND bt.enabled=1
               WHERE fn.membership_state='active'"""
        ).fetchall()
        candidates = [dict(row) for row in rows]

        # The master does not heartbeat to itself, so merge its live read-only
        # storage inventory directly rather than inventing a self-heartbeat.
        try:
            identity = load_node_identity()
        except Exception:
            identity = None
        if identity is not None:
            master = conn.execute(
                """SELECT hostname FROM fleet_nodes
                   WHERE node_id=? AND role='master' AND membership_state='active'""",
                (identity.node_id,),
            ).fetchone()
            if master is not None:
                registered = {
                    str(row["filesystem_uuid"]): (int(row["id"]), str(row["friendly_name"]))
                    for row in conn.execute(
                        """SELECT id,filesystem_uuid,friendly_name FROM backup_targets
                           WHERE host_node_id=? AND enabled=1""",
                        (identity.node_id,),
                    ).fetchall()
                }
                try:
                    local_items = discover_storage()
                except Exception:
                    local_items = []
                remote_keys = {
                    (str(item["observer_node_id"]), str(item["filesystem_uuid"]))
                    for item in candidates
                }
                for item in local_items:
                    key = (identity.node_id, item.filesystem_uuid)
                    if key in remote_keys:
                        continue
                    existing = registered.get(item.filesystem_uuid)
                    candidates.append({
                        "observer_node_id": identity.node_id,
                        "host_hostname": str(master["hostname"]),
                        "filesystem_uuid": item.filesystem_uuid,
                        "name": item.name,
                        "device": item.device,
                        "filesystem_type": item.filesystem_type,
                        "mountpoint": item.mountpoint,
                        "size_bytes": item.size_bytes,
                        "removable": 1 if item.removable else 0,
                        "last_reported_at": None,
                        "registered_target_id": existing[0] if existing else None,
                        "registered_target_name": existing[1] if existing else None,
                    })
    finally:
        conn.close()

    result: list[dict] = []
    for raw in candidates:
        item = {
            "candidate_id": _candidate_id(
                str(raw["observer_node_id"]), str(raw["filesystem_uuid"])
            ),
            "host_node_id": str(raw["observer_node_id"]),
            "host_hostname": str(raw["host_hostname"]),
            "name": str(raw["name"]),
            "filesystem_type": str(raw["filesystem_type"]),
            "size_bytes": int(raw["size_bytes"] or 0),
            "removable": bool(raw["removable"]),
            "registered": raw["registered_target_id"] is not None,
            "registered_target_id": (
                int(raw["registered_target_id"])
                if raw["registered_target_id"] is not None else None
            ),
            "registered_target_name": raw["registered_target_name"],
        }
        if include_sensitive:
            item.update({
                "filesystem_uuid": str(raw["filesystem_uuid"]),
                "device": str(raw["device"]),
                "mountpoint": str(raw["mountpoint"]),
                "last_reported_at": raw["last_reported_at"],
            })
        result.append(item)
    return sorted(
        result,
        key=lambda value: (
            not value["removable"],
            value["host_hostname"].casefold(),
            value["name"].casefold(),
        ),
    )
