"""Master-side signed activation of pending Lattice fleet members."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3

from lattice.file_access.keys import (
    ensure_fleet_signing_identity,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    normalize_manifest,
    sign_manifest,
    verify_manifest,
)


DEFAULT_FLEET_SIGNING_DIR = Path("/etc/lattice/fleet-signing")


class FleetActivationError(RuntimeError):
    """Raised when a pending node cannot safely become active."""


@dataclass(frozen=True)
class FleetActivationCandidate:
    target_node_id: str
    generation: int
    manifest: dict
    signature: str


def _signing_dir() -> Path:
    override = os.environ.get("LATTICE_FLEET_SIGNING_DIR")
    return Path(override) if override else DEFAULT_FLEET_SIGNING_DIR


def _member_from_row(row) -> dict:
    values = {
        "node_id": row["node_id"], "hostname": row["hostname"], "role": row["role"],
        "main_user": row["main_user"], "file_public_key": row["file_public_key"],
        "file_host_public_key": row["file_host_public_key"],
        "file_host_key_fingerprint": row["file_host_key_fingerprint"],
        "file_key_generation": row["file_key_generation"],
    }
    required=("node_id","hostname","role","main_user","file_public_key","file_host_public_key","file_host_key_fingerprint")
    if not all(values[key] for key in required):
        raise FleetActivationError(f"Fleet node {row['node_id']} has incomplete file identity")
    shell = {
        "shell_public_key": row["shell_public_key"],
        "shell_host_public_key": row["shell_host_public_key"],
        "shell_host_key_fingerprint": row["shell_host_key_fingerprint"],
        "shell_key_generation": row["shell_key_generation"],
    }
    if any(shell.values()):
        if not all(shell.values()):
            raise FleetActivationError(f"Fleet node {row['node_id']} has incomplete shell identity")
        values.update(shell)
    return values


def _load_current_fleet(conn: sqlite3.Connection):
    row = conn.execute(
        """
        SELECT
            fleet_id,
            generation,
            manifest,
            signature,
            signing_public_key
        FROM fleet_state
        WHERE id = 1
        """
    ).fetchone()

    if row is None:
        raise FleetActivationError(
            "Master fleet state has not been initialized"
        )

    try:
        manifest = normalize_manifest(
            json.loads(row["manifest"])
        )
    except (json.JSONDecodeError, FleetManifestError) as exc:
        raise FleetActivationError(
            "Current fleet manifest is invalid"
        ) from exc

    if manifest["fleet_id"] != row["fleet_id"]:
        raise FleetActivationError(
            "Current fleet ID does not match its manifest"
        )

    if manifest["generation"] != row["generation"]:
        raise FleetActivationError(
            "Current fleet generation does not match its manifest"
        )

    if not verify_manifest(
        manifest,
        row["signature"],
        row["signing_public_key"],
    ):
        raise FleetActivationError(
            "Current fleet signature is invalid"
        )

    return row, manifest


def stage_worker_activation(
    conn: sqlite3.Connection,
    *,
    target_node_id: str,
) -> FleetActivationCandidate:
    """Create or return one durable next-generation activation candidate."""
    target = conn.execute(
        """
        SELECT *
        FROM fleet_nodes
        WHERE node_id = ?
        """,
        (target_node_id,),
    ).fetchone()

    if target is None:
        raise FleetActivationError(
            "Pending worker identity does not exist"
        )

    if target["role"] != "worker":
        raise FleetActivationError(
            "Only a worker can use worker activation"
        )

    if target["membership_state"] == "active":
        raise FleetActivationError(
            "Worker is already active"
        )

    if target["membership_state"] != "pending":
        raise FleetActivationError(
            "Worker is not in pending membership state"
        )

    state, _ = _load_current_fleet(conn)
    current_generation = int(state["generation"])
    if conn.execute("SELECT 1 FROM shell_key_rotations LIMIT 1").fetchone() is not None:
        raise FleetActivationError(
            "A shell key rotation is in progress; finish it before activating another worker"
        )
    if conn.execute("SELECT 1 FROM file_key_rotations LIMIT 1").fetchone() is not None:
        raise FleetActivationError(
            "A file key rotation is in progress; finish it before activating another worker"
        )

    existing = conn.execute(
        """
        SELECT generation, manifest, signature
        FROM fleet_pending_updates
        WHERE target_node_id = ?
        """,
        (target_node_id,),
    ).fetchone()

    if existing is not None:
        if int(existing["generation"]) == current_generation + 1:
            try:
                manifest = normalize_manifest(
                    json.loads(existing["manifest"])
                )
            except (
                json.JSONDecodeError,
                FleetManifestError,
            ) as exc:
                raise FleetActivationError(
                    "Staged fleet update is invalid"
                ) from exc

            if not verify_manifest(
                manifest,
                existing["signature"],
                state["signing_public_key"],
            ):
                raise FleetActivationError(
                    "Staged fleet update signature is invalid"
                )

            return FleetActivationCandidate(
                target_node_id=target_node_id,
                generation=int(existing["generation"]),
                manifest=manifest,
                signature=existing["signature"],
            )

        conn.execute(
            """
            DELETE FROM fleet_pending_updates
            WHERE target_node_id = ?
            """,
            (target_node_id,),
        )

    other = conn.execute(
        """
        SELECT target_node_id
        FROM fleet_pending_updates
        LIMIT 1
        """
    ).fetchone()

    if other is not None:
        raise FleetActivationError(
            "Another fleet membership update is already pending"
        )

    signing = ensure_fleet_signing_identity(
        _signing_dir()
    )

    if signing.public_key_text != state["signing_public_key"]:
        raise FleetActivationError(
            "Fleet signing private key does not match pinned public key"
        )

    rows = conn.execute(
        """
        SELECT *
        FROM fleet_nodes
        WHERE membership_state = 'active'
           OR node_id = ?
        ORDER BY node_id
        """,
        (target_node_id,),
    ).fetchall()

    members = [_member_from_row(row) for row in rows]

    revoked = [
        row["node_id"]
        for row in conn.execute(
            """
            SELECT node_id
            FROM fleet_nodes
            WHERE membership_state = 'revoked'
            ORDER BY node_id
            """
        ).fetchall()
    ]

    generation = current_generation + 1

    manifest = normalize_manifest(
        {
            "schema_version": 1,
            "fleet_id": state["fleet_id"],
            "generation": generation,
            "members": members,
            "revoked": revoked,
        }
    )

    signature = sign_manifest(
        manifest,
        signing.private_key,
    )

    if not verify_manifest(
        manifest,
        signature,
        signing.public_key_text,
    ):
        raise FleetActivationError(
            "New fleet generation failed self-verification"
        )

    conn.execute(
        """
        INSERT INTO fleet_pending_updates (
            target_node_id,
            generation,
            manifest,
            signature
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            target_node_id,
            generation,
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
            ),
            signature,
        ),
    )

    return FleetActivationCandidate(
        target_node_id=target_node_id,
        generation=generation,
        manifest=manifest,
        signature=signature,
    )


def discard_unacknowledged_worker_activation(
    conn: sqlite3.Connection,
    *,
    target_node_id: str,
    generation: int,
) -> bool:
    """Discard only a staged candidate known not to have been accepted.

    This is intentionally not a generic stale-row cleanup: once a worker may
    have ACKed a generation, deleting it without reconciling that worker would
    be unsafe.
    """
    pending = conn.execute(
        """SELECT generation FROM fleet_pending_updates
           WHERE target_node_id = ?""",
        (target_node_id,),
    ).fetchone()
    target = conn.execute(
        """SELECT membership_state FROM fleet_nodes
           WHERE node_id = ?""",
        (target_node_id,),
    ).fetchone()
    current = conn.execute(
        "SELECT generation FROM fleet_state WHERE id = 1"
    ).fetchone()
    if pending is None:
        return False
    if target is None or target["membership_state"] != "pending":
        raise FleetActivationError(
            "Refusing to discard activation for a worker that is no longer pending"
        )
    if current is None or int(current["generation"]) != generation - 1:
        raise FleetActivationError(
            "Refusing to discard activation after the fleet generation changed"
        )
    if int(pending["generation"]) != generation:
        raise FleetActivationError(
            "Refusing to discard a different staged fleet generation"
        )
    conn.execute(
        """DELETE FROM fleet_pending_updates
           WHERE target_node_id = ? AND generation = ?""",
        (target_node_id, generation),
    )
    return True


def reconcile_pending_worker_activation(
    conn: sqlite3.Connection,
    *,
    target_node_id: str,
    reported_generation: int,
) -> str:
    """Reconcile one interrupted activation from authenticated worker reality.

    A worker reporting the exact staged generation proves the signed candidate
    was durably applied, so the master may commit it. A worker reporting an
    older durable generation proves the candidate was not applied and may be
    safely discarded. Newer/invalid state is contradictory and is preserved
    for operator investigation.
    """
    if isinstance(reported_generation, bool) or not isinstance(reported_generation, int):
        raise FleetActivationError("Worker reported an invalid fleet generation")
    if reported_generation < 0:
        raise FleetActivationError("Worker reported an invalid fleet generation")

    pending = conn.execute(
        """SELECT generation FROM fleet_pending_updates
           WHERE target_node_id = ?""",
        (target_node_id,),
    ).fetchone()
    if pending is None:
        return "no_pending"

    generation = int(pending["generation"])
    if reported_generation == generation:
        commit_worker_activation(
            conn,
            target_node_id=target_node_id,
            generation=generation,
        )
        return "committed"

    if reported_generation < generation:
        discarded = discard_unacknowledged_worker_activation(
            conn,
            target_node_id=target_node_id,
            generation=generation,
        )
        return "discarded" if discarded else "no_pending"

    raise FleetActivationError(
        "Worker reports a fleet generation newer than the staged activation"
    )


def commit_worker_activation(
    conn: sqlite3.Connection,
    *,
    target_node_id: str,
    generation: int,
) -> None:
    """Commit a generation only after the worker ACKs that exact generation."""
    pending = conn.execute(
        """
        SELECT generation, manifest, signature
        FROM fleet_pending_updates
        WHERE target_node_id = ?
        """,
        (target_node_id,),
    ).fetchone()

    target = conn.execute(
        """
        SELECT membership_state, membership_generation
        FROM fleet_nodes
        WHERE node_id = ?
        """,
        (target_node_id,),
    ).fetchone()

    if target is None:
        raise FleetActivationError(
            "Target worker disappeared before activation commit"
        )

    current = conn.execute(
        """
        SELECT generation, signing_public_key
        FROM fleet_state
        WHERE id = 1
        """
    ).fetchone()

    if current is None:
        raise FleetActivationError(
            "Master fleet state disappeared before activation commit"
        )

    if (
        target["membership_state"] == "active"
        and int(target["membership_generation"]) == generation
        and int(current["generation"]) == generation
    ):
        conn.execute(
            """
            DELETE FROM fleet_pending_updates
            WHERE target_node_id = ?
            """,
            (target_node_id,),
        )
        return

    if pending is None:
        raise FleetActivationError(
            "No staged fleet generation exists for this worker"
        )

    if int(pending["generation"]) != generation:
        raise FleetActivationError(
            "Worker acknowledged a different fleet generation"
        )

    if int(current["generation"]) != generation - 1:
        raise FleetActivationError(
            "Fleet generation changed before activation commit"
        )

    try:
        manifest = normalize_manifest(
            json.loads(pending["manifest"])
        )
    except (
        json.JSONDecodeError,
        FleetManifestError,
    ) as exc:
        raise FleetActivationError(
            "Staged fleet manifest is invalid"
        ) from exc

    if not verify_manifest(
        manifest,
        pending["signature"],
        current["signing_public_key"],
    ):
        raise FleetActivationError(
            "Staged fleet manifest signature is invalid"
        )

    member_ids = {
        member["node_id"]
        for member in manifest["members"]
    }

    if target_node_id not in member_ids:
        raise FleetActivationError(
            "Worker ACKed a generation that does not contain itself"
        )

    conn.execute(
        """
        UPDATE fleet_state
        SET generation = ?,
            manifest = ?,
            signature = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = 1
        """,
        (
            generation,
            json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
            ),
            pending["signature"],
        ),
    )

    # The master obviously possesses the generation it just committed.
    conn.execute(
        """
        UPDATE fleet_nodes
        SET membership_generation = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE role = 'master'
          AND membership_state = 'active'
        """,
        (generation,),
    )

    # Existing peers may still have an older generation while offline.
    # Their membership_generation intentionally remains unchanged until ACK.
    conn.execute(
        """
        UPDATE fleet_nodes
        SET membership_state = 'active',
            membership_generation = ?,
            revoked_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE node_id = ?
          AND membership_state = 'pending'
        """,
        (generation, target_node_id),
    )

    conn.execute(
        """
        DELETE FROM fleet_pending_updates
        WHERE target_node_id = ?
        """,
        (target_node_id,),
    )


def revoke_worker_membership(
    conn: sqlite3.Connection,
    *,
    target_node_id: str,
) -> FleetActivationCandidate:
    """Immediately publish a new signed generation that revokes one active worker.

    Revocation is master-authoritative and deliberately does not wait for the
    removed worker to ACK. Remaining peers learn the newer signed generation
    through their normal authenticated heartbeat synchronization.
    """
    target = conn.execute(
        "SELECT * FROM fleet_nodes WHERE node_id = ?", (target_node_id,)
    ).fetchone()
    if target is None or target["role"] != "worker":
        raise FleetActivationError("Worker fleet identity does not exist")
    if target["membership_state"] == "revoked":
        state, manifest = _load_current_fleet(conn)
        return FleetActivationCandidate(
            target_node_id=target_node_id, generation=int(state["generation"]),
            manifest=manifest, signature=state["signature"],
        )
    if target["membership_state"] != "active":
        raise FleetActivationError("Only an active worker can be revoked")
    if conn.execute("SELECT 1 FROM fleet_pending_updates LIMIT 1").fetchone() is not None:
        raise FleetActivationError("A fleet membership update is already pending")

    state, current_manifest = _load_current_fleet(conn)
    signing = ensure_fleet_signing_identity(_signing_dir())
    if signing.public_key_text != state["signing_public_key"]:
        raise FleetActivationError("Fleet signing private key does not match pinned public key")

    # Preserve any signed file/shell overlap keys for unrelated active members.
    # Revocation is allowed to interrupt a rollout, but must never silently
    # discard the overlap that makes old/new keys mutually compatible.
    members = [
        dict(member)
        for member in current_manifest["members"]
        if member["node_id"] != target_node_id
    ]
    revoked = set(current_manifest["revoked"])
    revoked.add(target_node_id)
    generation = int(state["generation"]) + 1
    manifest = normalize_manifest({
        "schema_version": 1, "fleet_id": state["fleet_id"],
        "generation": generation, "members": members, "revoked": sorted(revoked),
    })
    signature = sign_manifest(manifest, signing.private_key)
    if not verify_manifest(manifest, signature, signing.public_key_text):
        raise FleetActivationError("Revocation generation failed self-verification")

    conn.execute(
        """UPDATE fleet_state SET generation=?, manifest=?, signature=?,
           updated_at=CURRENT_TIMESTAMP WHERE id=1""",
        (generation, json.dumps(manifest, sort_keys=True, separators=(",", ":")), signature),
    )
    conn.execute(
        """UPDATE fleet_nodes SET membership_state='revoked', revoked_at=CURRENT_TIMESTAMP,
           membership_generation=?, updated_at=CURRENT_TIMESTAMP WHERE node_id=?""",
        (generation, target_node_id),
    )
    conn.execute(
        """UPDATE fleet_nodes SET membership_generation=?, updated_at=CURRENT_TIMESTAMP
           WHERE role='master' AND membership_state='active'""",
        (generation,),
    )
    for table in ("shell_key_rotations", "file_key_rotations"):
        rotation = conn.execute(
            f"SELECT target_node_id FROM {table} LIMIT 1"
        ).fetchone()
        if rotation is None:
            continue
        if rotation["target_node_id"] == target_node_id:
            conn.execute(
                f"DELETE FROM {table} WHERE target_node_id=?",
                (target_node_id,),
            )
        else:
            conn.execute(
                f"""UPDATE {table}
                    SET overlap_generation=?, stage='overlap', updated_at=CURRENT_TIMESTAMP
                    WHERE target_node_id=?""",
                (generation, rotation["target_node_id"]),
            )
    return FleetActivationCandidate(
        target_node_id=target_node_id, generation=generation,
        manifest=manifest, signature=signature,
    )
