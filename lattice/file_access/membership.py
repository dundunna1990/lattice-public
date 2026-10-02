"""Validation and persistence of peer file identities."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3
import uuid

from lattice.file_access.keys import (
    FileKeyError,
    fingerprint_ed25519_public_key,
    validate_ed25519_public_key,
)


class FleetIdentityError(ValueError):
    """Raised when advertised fleet identity cannot be trusted."""


@dataclass(frozen=True)
class PeerFileIdentity:
    node_id: str
    main_user: str
    main_uid: int
    main_gid: int
    file_public_key: str
    file_host_public_key: str
    file_host_key_fingerprint: str
    file_key_generation: int
    shell_public_key: str | None = None
    shell_host_public_key: str | None = None
    shell_host_key_fingerprint: str | None = None
    shell_key_generation: int = 0
    backup_public_key: str | None = None
    backup_host_public_key: str | None = None
    backup_host_key_fingerprint: str | None = None
    backup_key_generation: int = 0


def _uuid4(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise FleetIdentityError("Peer node ID is invalid") from exc

    if parsed.version != 4:
        raise FleetIdentityError("Peer node ID must be UUIDv4")

    return str(parsed)


def validate_worker_file_offer(
    payload: object,
    *,
    expected_hostname: str,
) -> PeerFileIdentity:
    """Validate the permanent file identity in a worker pairing offer."""
    if not isinstance(payload, dict):
        raise FleetIdentityError("Worker pairing offer is invalid")

    if payload.get("hostname") != expected_hostname:
        raise FleetIdentityError(
            "Worker file identity hostname does not match pairing target"
        )

    main_user = payload.get("main_user")
    if not isinstance(main_user, str) or not main_user.strip():
        raise FleetIdentityError("Worker main user is invalid")
    main_user = main_user.strip()

    main_uid = payload.get("main_uid")
    main_gid = payload.get("main_gid")

    if isinstance(main_uid, bool) or not isinstance(main_uid, int) or main_uid <= 0:
        raise FleetIdentityError("Worker main user ID is invalid")

    if isinstance(main_gid, bool) or not isinstance(main_gid, int) or main_gid < 0:
        raise FleetIdentityError("Worker main group ID is invalid")

    try:
        file_public_key = validate_ed25519_public_key(
            payload["file_public_key"]
        )
        file_host_public_key = validate_ed25519_public_key(
            payload["file_host_public_key"]
        )
    except (KeyError, FileKeyError) as exc:
        raise FleetIdentityError(
            "Worker file SSH identity is invalid"
        ) from exc

    advertised_fingerprint = payload.get("file_host_key_fingerprint")
    if not isinstance(advertised_fingerprint, str):
        raise FleetIdentityError("Worker file host fingerprint is missing")
    actual_fingerprint = fingerprint_ed25519_public_key(file_host_public_key)
    if advertised_fingerprint != actual_fingerprint:
        raise FleetIdentityError("Worker file host fingerprint does not match its host key")

    shell_fields = (
        payload.get("shell_public_key"), payload.get("shell_host_public_key"),
        payload.get("shell_host_key_fingerprint"), payload.get("shell_key_generation"),
    )
    shell_present = any(value is not None for value in shell_fields)
    shell_public_key = shell_host_public_key = shell_actual_fingerprint = None
    shell_generation = 0
    if shell_present:
        if any(value is None for value in shell_fields):
            raise FleetIdentityError("Worker shell SSH identity is incomplete")
        try:
            shell_public_key = validate_ed25519_public_key(payload["shell_public_key"])
            shell_host_public_key = validate_ed25519_public_key(payload["shell_host_public_key"])
        except FileKeyError as exc:
            raise FleetIdentityError("Worker shell SSH identity is invalid") from exc
        shell_actual_fingerprint = fingerprint_ed25519_public_key(shell_host_public_key)
        if payload["shell_host_key_fingerprint"] != shell_actual_fingerprint:
            raise FleetIdentityError("Worker shell host fingerprint does not match its host key")
        if " ".join(shell_public_key.split()[:2]) == " ".join(file_public_key.split()[:2]):
            raise FleetIdentityError("Worker shell and file client keys must be separate")
        if " ".join(shell_host_public_key.split()[:2]) == " ".join(file_host_public_key.split()[:2]):
            raise FleetIdentityError("Worker shell and file host keys must be separate")
        shell_generation = payload["shell_key_generation"]
        if isinstance(shell_generation, bool) or not isinstance(shell_generation, int) or shell_generation < 1:
            raise FleetIdentityError("Worker shell key generation is invalid")

    backup_fields = (
        payload.get("backup_public_key"), payload.get("backup_host_public_key"),
        payload.get("backup_host_key_fingerprint"), payload.get("backup_key_generation"),
    )
    backup_present = any(value is not None for value in backup_fields)
    backup_public_key = backup_host_public_key = backup_actual_fingerprint = None
    backup_generation = 0
    if backup_present:
        if any(value is None for value in backup_fields):
            raise FleetIdentityError("Worker backup SSH identity is incomplete")
        try:
            backup_public_key = validate_ed25519_public_key(payload["backup_public_key"])
            backup_host_public_key = validate_ed25519_public_key(payload["backup_host_public_key"])
        except FileKeyError as exc:
            raise FleetIdentityError("Worker backup SSH identity is invalid") from exc
        backup_actual_fingerprint = fingerprint_ed25519_public_key(backup_host_public_key)
        if payload["backup_host_key_fingerprint"] != backup_actual_fingerprint:
            raise FleetIdentityError("Worker backup host fingerprint does not match its host key")
        client_identities = {
            " ".join(file_public_key.split()[:2]),
            *(
                [" ".join(shell_public_key.split()[:2])]
                if shell_public_key is not None else []
            ),
        }
        host_identities = {
            " ".join(file_host_public_key.split()[:2]),
            *(
                [" ".join(shell_host_public_key.split()[:2])]
                if shell_host_public_key is not None else []
            ),
        }
        if " ".join(backup_public_key.split()[:2]) in client_identities:
            raise FleetIdentityError("Worker backup client key must be separate from other channels")
        if " ".join(backup_host_public_key.split()[:2]) in host_identities:
            raise FleetIdentityError("Worker backup host key must be separate from other channels")
        backup_generation = payload["backup_key_generation"]
        if isinstance(backup_generation, bool) or not isinstance(backup_generation, int) or backup_generation < 1:
            raise FleetIdentityError("Worker backup key generation is invalid")

    generation = payload.get("file_key_generation")
    if (
        isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise FleetIdentityError(
            "Worker file key generation is invalid"
        )

    return PeerFileIdentity(
        node_id=_uuid4(payload.get("node_id")),
        main_user=main_user,
        main_uid=main_uid,
        main_gid=main_gid,
        file_public_key=file_public_key,
        file_host_public_key=file_host_public_key,
        file_host_key_fingerprint=actual_fingerprint,
        file_key_generation=generation,
        shell_public_key=shell_public_key,
        shell_host_public_key=shell_host_public_key,
        shell_host_key_fingerprint=shell_actual_fingerprint,
        shell_key_generation=shell_generation,
        backup_public_key=backup_public_key,
        backup_host_public_key=backup_host_public_key,
        backup_host_key_fingerprint=backup_actual_fingerprint,
        backup_key_generation=backup_generation,
    )


def record_worker_file_identity(
    conn: sqlite3.Connection,
    *,
    worker_id: int,
    hostname: str,
    ip: str,
    identity: PeerFileIdentity,
) -> None:
    """Persist a verified peer identity after ordinary pairing succeeds."""
    if worker_id <= 0:
        raise FleetIdentityError("Worker database ID is invalid")

    existing = conn.execute(
        """
        SELECT worker_id, membership_state
        FROM fleet_nodes
        WHERE node_id = ?
        """,
        (identity.node_id,),
    ).fetchone()

    if (
        existing is not None
        and existing[0] not in (None, worker_id)
        and existing[1] != "revoked"
    ):
        raise FleetIdentityError(
            "Peer node ID is already attached to another active worker"
        )

    now = datetime.now(timezone.utc).isoformat()

    # If the same master-side worker record is being re-paired to a genuinely
    # different permanent node, retain the old node as a security tombstone.
    conn.execute(
        """
        UPDATE fleet_nodes
        SET membership_state = 'revoked',
            revoked_at = COALESCE(revoked_at, ?),
            updated_at = ?
        WHERE worker_id = ?
          AND node_id != ?
          AND membership_state != 'revoked'
        """,
        (now, now, worker_id, identity.node_id),
    )

    conn.execute(
        """
        INSERT INTO fleet_nodes (
            node_id,
            worker_id,
            hostname,
            role,
            main_user,
            main_uid,
            main_gid,
            file_public_key,
            file_key_generation,
            file_host_public_key,
            file_host_key_fingerprint,
            shell_public_key,
            shell_key_generation,
            shell_host_public_key,
            shell_host_key_fingerprint,
            backup_public_key,
            backup_key_generation,
            backup_host_public_key,
            backup_host_key_fingerprint,
            last_known_ip,
            membership_state,
            membership_generation,
            revoked_at,
            created_at,
            updated_at
        )
        VALUES (
            ?, ?, ?, 'worker', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            'pending', 0, NULL, ?, ?
        )
        ON CONFLICT(node_id) DO UPDATE SET
            worker_id = excluded.worker_id,
            hostname = excluded.hostname,
            role = 'worker',
            main_user = excluded.main_user,
            main_uid = excluded.main_uid,
            main_gid = excluded.main_gid,
            file_public_key = excluded.file_public_key,
            file_key_generation = excluded.file_key_generation,
            file_host_public_key = excluded.file_host_public_key,
            file_host_key_fingerprint =
                excluded.file_host_key_fingerprint,
            shell_public_key = excluded.shell_public_key,
            shell_key_generation = excluded.shell_key_generation,
            shell_host_public_key = excluded.shell_host_public_key,
            shell_host_key_fingerprint = excluded.shell_host_key_fingerprint,
            backup_public_key = excluded.backup_public_key,
            backup_key_generation = excluded.backup_key_generation,
            backup_host_public_key = excluded.backup_host_public_key,
            backup_host_key_fingerprint = excluded.backup_host_key_fingerprint,
            last_known_ip = excluded.last_known_ip,
            membership_state = 'pending',
            membership_generation = 0,
            revoked_at = NULL,
            updated_at = excluded.updated_at
        """,
        (
            identity.node_id,
            worker_id,
            hostname,
            identity.main_user,
            identity.main_uid,
            identity.main_gid,
            identity.file_public_key,
            identity.file_key_generation,
            identity.file_host_public_key,
            identity.file_host_key_fingerprint,
            identity.shell_public_key,
            identity.shell_key_generation,
            identity.shell_host_public_key,
            identity.shell_host_key_fingerprint,
            identity.backup_public_key,
            identity.backup_key_generation,
            identity.backup_host_public_key,
            identity.backup_host_key_fingerprint,
            ip,
            now,
            now,
        ),
    )
