"""Master-side generation of signed backup source-to-target assignments."""
from __future__ import annotations

import json
from pathlib import Path

from lattice.backup.assignment import normalize_assignment, sign_assignment
from lattice.backup.identity import ensure_local_backup_identity_record
from lattice.backup.config_state import reconcile_config_state
from lattice.backup.sync import BackupSyncError, ensure_backup_transport_current
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import DEFAULT_FLEET_SIGNING_DIR


class BackupAssignmentStateError(RuntimeError):
    pass


def _ensure_local_transport(state: dict) -> None:
    identity = load_node_identity()
    if identity is None:
        raise BackupAssignmentStateError("Permanent local Node ID is unavailable")
    public_key_path = DEFAULT_FLEET_SIGNING_DIR / "fleet_signing_ed25519.pub"
    try:
        signing_public_key = public_key_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise BackupAssignmentStateError(
            f"Could not read fleet signing public key: {exc}"
        ) from exc
    try:
        ensure_backup_transport_current(
            assignment=state["assignment"],
            signature=state["signature"],
            signing_public_key=signing_public_key,
        )
    except BackupSyncError as exc:
        raise BackupAssignmentStateError(str(exc)) from exc


def _assignment_rows(conn) -> list[dict]:
    rows = conn.execute(
        """SELECT bj.job_uuid, bj.source_node_id, bt.target_uuid,
                  bt.host_node_id AS target_node_id,
                  src.backup_public_key,
                  dst.backup_host_public_key,
                  dst.backup_host_key_fingerprint
           FROM backup_jobs AS bj
           JOIN backup_targets AS bt ON bt.id=bj.target_id
           JOIN fleet_nodes AS src ON src.node_id=bj.source_node_id
           JOIN fleet_nodes AS dst ON dst.node_id=bt.host_node_id
           WHERE bj.enabled=1 AND bj.paused=0 AND bt.enabled=1
             AND bj.source_node_id != bt.host_node_id
             AND src.membership_state='active'
             AND dst.membership_state='active'
           ORDER BY bt.host_node_id, bj.source_node_id, bt.target_uuid"""
    ).fetchall()
    result = []
    for row in rows:
        if not row["backup_public_key"]:
            raise BackupAssignmentStateError(
                f"Source {row['source_node_id']} has not enrolled a backup identity yet"
            )
        if not row["backup_host_public_key"] or not row["backup_host_key_fingerprint"]:
            raise BackupAssignmentStateError(
                f"Target {row['target_node_id']} has not enrolled a backup host identity yet"
            )
        result.append({
            "source_node_id": row["source_node_id"],
            "target_node_id": row["target_node_id"],
            "target_uuid": row["target_uuid"],
            "repository_id": row["job_uuid"],
            "backup_public_key": row["backup_public_key"],
            "backup_host_public_key": row["backup_host_public_key"],
            "backup_host_key_fingerprint": row["backup_host_key_fingerprint"],
        })
    return result


def reconcile_assignment_state(
    *,
    signing_private_key: Path | None = None,
) -> dict:
    """Return the current signed assignment, advancing only when assignments change."""
    key = signing_private_key or DEFAULT_FLEET_SIGNING_DIR / "fleet_signing_ed25519"
    ensure_local_backup_identity_record()
    conn = get_db_connection()
    try:
        fleet = conn.execute("SELECT fleet_id FROM fleet_state WHERE id=1").fetchone()
        if fleet is None:
            raise BackupAssignmentStateError("Fleet state is not initialized")
        assignments = _assignment_rows(conn)
        previous = conn.execute(
            "SELECT generation, assignment, signature FROM backup_assignment_state WHERE id=1"
        ).fetchone()
        if previous is not None:
            try:
                old = normalize_assignment(json.loads(previous["assignment"]))
            except Exception as exc:
                raise BackupAssignmentStateError("Saved backup assignment state is invalid") from exc
            if old["assignments"] == assignments:
                state = {"assignment": old, "signature": previous["signature"]}
                _ensure_local_transport(state)
                return state
            generation = int(previous["generation"]) + 1
        else:
            generation = 1
        candidate = normalize_assignment({
            "schema_version": 1,
            "fleet_id": fleet["fleet_id"],
            "generation": generation,
            "assignments": assignments,
        })
        signature = sign_assignment(candidate, key)
        conn.execute(
            """INSERT INTO backup_assignment_state(id,generation,assignment,signature)
               VALUES(1,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 generation=excluded.generation,
                 assignment=excluded.assignment,
                 signature=excluded.signature,
                 updated_at=CURRENT_TIMESTAMP""",
            (generation, json.dumps(candidate, sort_keys=True, separators=(",", ":")), signature),
        )
        conn.commit()
        state = {"assignment": candidate, "signature": signature}
        _ensure_local_transport(state)
        return state
    finally:
        conn.close()


def main() -> None:
    import os
    role_path = Path("/etc/lattice/role")
    if os.geteuid() != 0:
        raise SystemExit("Backup assignment reconciliation must run as root")
    try:
        role = role_path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"Could not read Lattice role: {exc}") from exc
    if role != "master":
        return
    config_state = reconcile_config_state()
    state = reconcile_assignment_state()
    print(
        f"Backup config generation {config_state['config']['generation']} contains "
        f"{len(config_state['config']['jobs'])} job(s); "
        f"transport generation {state['assignment']['generation']} contains "
        f"{len(state['assignment']['assignments'])} remote assignment(s)"
    )


if __name__ == "__main__":
    main()


def current_assignment_state() -> dict | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT assignment, signature FROM backup_assignment_state WHERE id=1"
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    try:
        assignment = normalize_assignment(json.loads(row["assignment"]))
    except Exception as exc:
        raise BackupAssignmentStateError("Saved backup assignment state is invalid") from exc
    return {"assignment": assignment, "signature": str(row["signature"])}
