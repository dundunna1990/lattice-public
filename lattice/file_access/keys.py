"""Dedicated cryptographic identities for the Lattice file layer."""

from __future__ import annotations

import base64
import hashlib
import os
import grp
from dataclasses import dataclass
from pathlib import Path
import subprocess


DEFAULT_FILE_SSH_DIR = Path("/etc/lattice/file-ssh")
DEFAULT_FLEET_SIGNING_DIR = Path("/etc/lattice/fleet-signing")


class FileKeyError(RuntimeError):
    """Raised when a Lattice file-layer key cannot be handled safely."""


@dataclass(frozen=True)
class KeyPair:
    private_key: Path
    public_key: Path
    public_key_text: str
    fingerprint: str


def validate_ed25519_public_key(public_key: str) -> str:
    """Validate and normalize one OpenSSH Ed25519 public key."""
    if not isinstance(public_key, str):
        raise FileKeyError("Public key must be text")

    if "\n" in public_key or "\r" in public_key:
        raise FileKeyError("Public key must be exactly one line")

    value = public_key.strip()
    fields = value.split()

    if len(fields) not in (2, 3):
        raise FileKeyError("Public key has an invalid OpenSSH format")

    if fields[0] != "ssh-ed25519":
        raise FileKeyError("Only Ed25519 keys are permitted")

    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except Exception as exc:
        raise FileKeyError("Public key is not valid base64") from exc

    if len(decoded) < 4:
        raise FileKeyError("Public key data is truncated")

    algorithm_length = int.from_bytes(decoded[0:4], "big")
    algorithm_end = 4 + algorithm_length

    if algorithm_end + 4 > len(decoded):
        raise FileKeyError("Public key algorithm data is truncated")

    algorithm = decoded[4:algorithm_end]

    key_length = int.from_bytes(
        decoded[algorithm_end:algorithm_end + 4],
        "big",
    )
    key_start = algorithm_end + 4
    key_end = key_start + key_length

    if (
        algorithm != b"ssh-ed25519"
        or key_length != 32
        or key_end != len(decoded)
    ):
        raise FileKeyError("Public key is not a valid Ed25519 key")

    return value


def fingerprint_ed25519_public_key(public_key: str) -> str:
    """Return the OpenSSH SHA256 fingerprint for one validated key."""
    value = validate_ed25519_public_key(public_key)
    key_blob = base64.b64decode(value.split()[1], validate=True)
    digest = base64.b64encode(
        hashlib.sha256(key_blob).digest()
    ).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _fingerprint(public_key_path: Path) -> str:
    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-lf",
                str(public_key_path),
                "-E",
                "sha256",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FileKeyError(f"Could not fingerprint public key: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise FileKeyError(f"Could not fingerprint public key: {detail}")

    fields = result.stdout.strip().split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise FileKeyError("ssh-keygen returned an invalid fingerprint")

    return fields[1]


def _ensure_keypair(
    directory: Path,
    name: str,
    comment: str,
) -> KeyPair:
    directory.mkdir(parents=True, exist_ok=True)

    # Tests/custom key directories remain private to their owner. The
    # production file-key directory is root:lattice 0750 so Lattice's
    # unprivileged mount process can use the client key while the host
    # private key stays root-only.
    if os.geteuid() == 0 or directory.stat().st_uid == os.geteuid():
        os.chmod(directory, 0o700)

    private_key = directory / name
    public_key = directory / f"{name}.pub"

    if private_key.exists() != public_key.exists():
        raise FileKeyError(
            f"Incomplete keypair at {private_key}; "
            "restore the matching key instead of silently replacing it"
        )

    if not private_key.exists():
        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-q",
                    "-t",
                    "ed25519",
                    "-f",
                    str(private_key),
                    "-N",
                    "",
                    "-C",
                    comment,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FileKeyError(f"Could not generate Ed25519 key: {exc}") from exc

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise FileKeyError(f"Could not generate Ed25519 key: {detail}")

    # Production file-transport private keys are root-only.
    # OpenSSH refuses client private keys that are group-readable.
    if (
        directory == DEFAULT_FILE_SSH_DIR
        and os.geteuid() == 0
    ):
        try:
            lattice_gid = grp.getgrnam("lattice").gr_gid
        except KeyError as exc:
            raise FileKeyError(
                "The lattice group is unavailable"
            ) from exc

        os.chown(directory, 0, lattice_gid)
        os.chmod(directory, 0o750)

        os.chown(private_key, 0, 0)
        os.chmod(private_key, 0o600)

        os.chown(public_key, 0, lattice_gid)
        os.chmod(public_key, 0o644)
    else:
        # Do not try to chmod root-owned production keys when this
        # function is merely reading them as the lattice service user.
        if private_key.stat().st_uid == os.geteuid():
            os.chmod(private_key, 0o600)
        if public_key.stat().st_uid == os.geteuid():
            os.chmod(public_key, 0o644)

    try:
        public_text = public_key.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise FileKeyError(f"Could not read generated public key: {exc}") from exc

    public_text = validate_ed25519_public_key(public_text)

    return KeyPair(
        private_key=private_key,
        public_key=public_key,
        public_key_text=public_text,
        fingerprint=_fingerprint(public_key),
    )


def ensure_file_client_identity(
    directory: Path = DEFAULT_FILE_SSH_DIR,
) -> KeyPair:
    """Identity used by this computer to authenticate for file access."""
    return _ensure_keypair(
        directory,
        "client_ed25519",
        "lattice-file-client",
    )


def ensure_file_host_identity(
    directory: Path = DEFAULT_FILE_SSH_DIR,
) -> KeyPair:
    """Host identity for the dedicated Lattice file SSH server."""
    return _ensure_keypair(
        directory,
        "host_ed25519",
        "lattice-file-host",
    )


def ensure_fleet_signing_identity(
    directory: Path = DEFAULT_FLEET_SIGNING_DIR,
) -> KeyPair:
    """Master-only identity used to sign fleet membership generations."""
    return _ensure_keypair(
        directory,
        "fleet_signing_ed25519",
        "lattice-fleet-signing",
    )
