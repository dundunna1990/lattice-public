"""Independent cryptographic identities for Lattice's admin shell channel."""
from __future__ import annotations

from pathlib import Path
from lattice.file_access.keys import KeyPair, _ensure_keypair

DEFAULT_SHELL_SSH_DIR = Path("/etc/lattice/shell-ssh")


def ensure_shell_client_identity(directory: Path = DEFAULT_SHELL_SSH_DIR) -> KeyPair:
    pair = _ensure_keypair(directory, "client_ed25519", "lattice-shell-client")
    if directory == DEFAULT_SHELL_SSH_DIR and __import__("os").geteuid() == 0:
        __import__("os").chmod(directory, 0o755)
        __import__("os").chmod(pair.public_key, 0o644)
    return pair


def ensure_shell_host_identity(directory: Path = DEFAULT_SHELL_SSH_DIR) -> KeyPair:
    pair = _ensure_keypair(directory, "host_ed25519", "lattice-shell-host")
    if directory == DEFAULT_SHELL_SSH_DIR and __import__("os").geteuid() == 0:
        __import__("os").chmod(directory, 0o755)
        __import__("os").chmod(pair.public_key, 0o644)
    return pair
