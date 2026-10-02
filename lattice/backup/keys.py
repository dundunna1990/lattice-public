"""Independent Ed25519 identities for the Lattice backup transport."""
from __future__ import annotations

from pathlib import Path
import grp
import os

from lattice.file_access.keys import KeyPair, _ensure_keypair

DEFAULT_BACKUP_SSH_DIR = Path("/etc/lattice/backup-ssh")



def _apply_production_permissions(directory: Path, pair: KeyPair) -> None:
    if directory != DEFAULT_BACKUP_SSH_DIR or os.geteuid() != 0:
        return
    try:
        lattice_gid = grp.getgrnam("lattice").gr_gid
    except KeyError as exc:
        raise RuntimeError("The lattice group is unavailable") from exc
    os.chown(directory, 0, lattice_gid)
    os.chmod(directory, 0o750)
    os.chown(pair.private_key, 0, 0)
    os.chmod(pair.private_key, 0o600)
    os.chown(pair.public_key, 0, lattice_gid)
    os.chmod(pair.public_key, 0o644)

def ensure_backup_client_identity(
    directory: Path = DEFAULT_BACKUP_SSH_DIR,
) -> KeyPair:
    pair = _ensure_keypair(
        directory,
        "client_ed25519",
        "lattice-backup-client",
    )
    _apply_production_permissions(directory, pair)
    return pair


def ensure_backup_host_identity(
    directory: Path = DEFAULT_BACKUP_SSH_DIR,
) -> KeyPair:
    pair = _ensure_keypair(
        directory,
        "host_ed25519",
        "lattice-backup-host",
    )
    _apply_production_permissions(directory, pair)
    return pair
