"""Local public identity advertised during trusted fleet enrollment."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from lattice.file_access.identity import (
    NodeIdentity,
    ensure_node_identity,
)
from lattice.file_access.keys import (
    KeyPair,
    ensure_file_client_identity,
    ensure_file_host_identity,
)
from lattice.shell_access.keys import (
    ensure_shell_client_identity,
    ensure_shell_host_identity,
)
from lattice.backup.keys import (
    ensure_backup_client_identity,
    ensure_backup_host_identity,
)


DEFAULT_FILE_SSH_DIR = Path("/etc/lattice/file-ssh")


@dataclass(frozen=True)
class LocalFileProfile:
    node: NodeIdentity
    client: KeyPair
    host: KeyPair
    shell_client: KeyPair
    shell_host: KeyPair
    backup_client: KeyPair
    backup_host: KeyPair

    @property
    def node_id(self) -> str:
        return self.node.node_id

    @property
    def main_user(self) -> str:
        return self.node.main_user

    @property
    def main_uid(self) -> int:
        return self.node.main_uid

    @property
    def main_gid(self) -> int:
        return self.node.main_gid


def _shell_ssh_dir() -> Path:
    override = os.environ.get("LATTICE_SHELL_SSH_DIR")
    if override:
        return Path(override)
    file_override = os.environ.get("LATTICE_FILE_SSH_DIR")
    if file_override:
        return Path(file_override).parent / "shell-ssh"
    return Path("/etc/lattice/shell-ssh")



def _backup_ssh_dir() -> Path:
    override = os.environ.get("LATTICE_BACKUP_SSH_DIR")
    if override:
        return Path(override)
    file_override = os.environ.get("LATTICE_FILE_SSH_DIR")
    if file_override:
        return Path(file_override).parent / "backup-ssh"
    return Path("/etc/lattice/backup-ssh")

def _file_ssh_dir() -> Path:
    override = os.environ.get("LATTICE_FILE_SSH_DIR")
    return Path(override) if override else DEFAULT_FILE_SSH_DIR


def _node_identity_path() -> Path | None:
    override = os.environ.get("LATTICE_NODE_IDENTITY_PATH")
    return Path(override) if override else None


def ensure_local_file_profile(main_user: str) -> LocalFileProfile:
    """Create or return this machine's permanent public file identity."""
    node = ensure_node_identity(
        main_user,
        path=_node_identity_path(),
    )

    directory = _file_ssh_dir()

    return LocalFileProfile(
        node=node,
        client=ensure_file_client_identity(directory),
        host=ensure_file_host_identity(directory),
        shell_client=ensure_shell_client_identity(_shell_ssh_dir()),
        shell_host=ensure_shell_host_identity(_shell_ssh_dir()),
        backup_client=ensure_backup_client_identity(_backup_ssh_dir()),
        backup_host=ensure_backup_host_identity(_backup_ssh_dir()),
    )
