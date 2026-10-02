"""Backup-channel public identity enrollment for already trusted fleet members."""
from __future__ import annotations

from dataclasses import dataclass

from lattice.backup.keys import (
    DEFAULT_BACKUP_SSH_DIR,
    ensure_backup_client_identity,
    ensure_backup_host_identity,
)
from lattice.file_access.identity import load_node_identity
from lattice.file_access.keys import fingerprint_ed25519_public_key, validate_ed25519_public_key


class BackupIdentityError(ValueError):
    pass


@dataclass(frozen=True)
class BackupPublicIdentity:
    node_id: str
    public_key: str
    host_public_key: str
    host_key_fingerprint: str
    key_generation: int = 1


def local_backup_identity() -> BackupPublicIdentity | None:
    identity = load_node_identity()
    if identity is None:
        return None
    client = ensure_backup_client_identity()
    host = ensure_backup_host_identity()
    return BackupPublicIdentity(
        node_id=identity.node_id,
        public_key=client.public_key_text,
        host_public_key=host.public_key_text,
        host_key_fingerprint=host.fingerprint,
    )




def read_local_backup_identity() -> BackupPublicIdentity | None:
    """Read an already-provisioned Backup identity without creating files."""
    identity = load_node_identity()
    if identity is None:
        return None
    client_public = DEFAULT_BACKUP_SSH_DIR / "client_ed25519.pub"
    host_public = DEFAULT_BACKUP_SSH_DIR / "host_ed25519.pub"
    if not client_public.exists() or not host_public.exists():
        return None
    try:
        client_text = validate_ed25519_public_key(
            client_public.read_text(encoding="utf-8").strip()
        )
        host_text = validate_ed25519_public_key(
            host_public.read_text(encoding="utf-8").strip()
        )
    except OSError as exc:
        raise BackupIdentityError(f"Could not read Backup public identity: {exc}") from exc
    return BackupPublicIdentity(
        node_id=identity.node_id,
        public_key=client_text,
        host_public_key=host_text,
        host_key_fingerprint=fingerprint_ed25519_public_key(host_text),
    )

def normalize_backup_identity(payload: object, *, expected_node_id: str) -> BackupPublicIdentity:
    if not isinstance(payload, dict):
        raise BackupIdentityError("Backup identity must be an object")
    if payload.get("node_id") != expected_node_id:
        raise BackupIdentityError("Backup identity has the wrong Node ID")
    try:
        public_key = validate_ed25519_public_key(payload["public_key"])
        host_public_key = validate_ed25519_public_key(payload["host_public_key"])
    except Exception as exc:
        raise BackupIdentityError("Backup SSH public identity is invalid") from exc
    fingerprint = payload.get("host_key_fingerprint")
    if fingerprint != fingerprint_ed25519_public_key(host_public_key):
        raise BackupIdentityError("Backup host fingerprint does not match its host key")
    generation = payload.get("key_generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation != 1:
        raise BackupIdentityError("Initial backup key generation must be 1")
    return BackupPublicIdentity(
        node_id=expected_node_id,
        public_key=public_key,
        host_public_key=host_public_key,
        host_key_fingerprint=fingerprint,
        key_generation=generation,
    )


def store_initial_backup_identity(conn, identity: BackupPublicIdentity) -> bool:
    """Pin a backup identity once; later drift is rejected rather than overwritten."""
    row = conn.execute(
        """SELECT membership_state, file_public_key, file_host_public_key,
                  shell_public_key, shell_host_public_key,
                  backup_public_key, backup_host_public_key,
                  backup_host_key_fingerprint, backup_key_generation
           FROM fleet_nodes WHERE node_id=?""",
        (identity.node_id,),
    ).fetchone()
    if row is None or row[0] != "active":
        raise BackupIdentityError("Backup identity owner is not an active fleet member")
    client_identity = " ".join(identity.public_key.split()[:2])
    host_identity = " ".join(identity.host_public_key.split()[:2])
    for value in (row[1], row[3]):
        if value and " ".join(str(value).split()[:2]) == client_identity:
            raise BackupIdentityError("Backup client key reuses another Lattice channel key")
    for value in (row[2], row[4]):
        if value and " ".join(str(value).split()[:2]) == host_identity:
            raise BackupIdentityError("Backup host key reuses another Lattice channel key")
    existing = row[5:9]
    if any(value not in (None, 0) for value in existing):
        expected = (
            identity.public_key,
            identity.host_public_key,
            identity.host_key_fingerprint,
            identity.key_generation,
        )
        if tuple(existing) != expected:
            raise BackupIdentityError("Pinned backup identity changed unexpectedly")
        return False
    conn.execute(
        """UPDATE fleet_nodes SET backup_public_key=?, backup_host_public_key=?,
                  backup_host_key_fingerprint=?, backup_key_generation=?, updated_at=CURRENT_TIMESTAMP
           WHERE node_id=?""",
        (
            identity.public_key, identity.host_public_key,
            identity.host_key_fingerprint, identity.key_generation, identity.node_id,
        ),
    )
    return True


async def store_initial_backup_identity_async(conn, identity: BackupPublicIdentity) -> bool:
    cursor = await conn.execute(
        """SELECT membership_state, file_public_key, file_host_public_key,
                  shell_public_key, shell_host_public_key,
                  backup_public_key, backup_host_public_key,
                  backup_host_key_fingerprint, backup_key_generation
           FROM fleet_nodes WHERE node_id=?""",
        (identity.node_id,),
    )
    row = await cursor.fetchone()
    if row is None or row[0] != "active":
        raise BackupIdentityError("Backup identity owner is not an active fleet member")
    client_identity = " ".join(identity.public_key.split()[:2])
    host_identity = " ".join(identity.host_public_key.split()[:2])
    for value in (row[1], row[3]):
        if value and " ".join(str(value).split()[:2]) == client_identity:
            raise BackupIdentityError("Backup client key reuses another Lattice channel key")
    for value in (row[2], row[4]):
        if value and " ".join(str(value).split()[:2]) == host_identity:
            raise BackupIdentityError("Backup host key reuses another Lattice channel key")
    existing = tuple(row[5:9])
    expected = (
        identity.public_key,
        identity.host_public_key,
        identity.host_key_fingerprint,
        identity.key_generation,
    )
    if any(value not in (None, 0) for value in existing):
        if existing != expected:
            raise BackupIdentityError("Pinned backup identity changed unexpectedly")
        return False
    await conn.execute(
        """UPDATE fleet_nodes SET backup_public_key=?, backup_host_public_key=?,
                  backup_host_key_fingerprint=?, backup_key_generation=?, updated_at=CURRENT_TIMESTAMP
           WHERE node_id=?""",
        (*expected, identity.node_id),
    )
    return True


def ensure_local_backup_identity_record() -> bool:
    """Generate/pin this node's backup identity in its local fleet database."""
    identity = local_backup_identity()
    if identity is None:
        raise BackupIdentityError("Permanent local Node ID is unavailable")
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    try:
        changed = store_initial_backup_identity(conn, identity)
        if changed:
            conn.commit()
        return changed
    finally:
        conn.close()
