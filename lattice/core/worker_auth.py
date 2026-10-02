"""Safe access to the distinct bearer token issued to each paired worker."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
import re
import stat


DEFAULT_TOKEN_DIR = Path("/etc/lattice/tokens")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


class WorkerAuthError(ValueError):
    """Raised when a worker identity or its saved token cannot be trusted."""


def validate_worker_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not _HOSTNAME_RE.fullmatch(hostname):
        raise WorkerAuthError("Worker hostname has an invalid format")
    return hostname


def _token_dir() -> Path:
    return Path(os.environ.get("LATTICE_TOKEN_DIR", DEFAULT_TOKEN_DIR))


def read_token_file(path: Path) -> str:
    """Read one bearer token without following links or accepting writable files."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise WorkerAuthError("Worker credential is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise WorkerAuthError("Worker credential is not a single regular file")
        if metadata.st_mode & 0o022:
            raise WorkerAuthError("Worker credential is writable by an unsafe account")
        if not 32 <= metadata.st_size <= 513:
            raise WorkerAuthError("Worker credential has an invalid size")
        raw = os.read(descriptor, 514)
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkerAuthError("Worker credential has an invalid encoding") from exc
    if "\r" in value or value.count("\n") > 1 or ("\n" in value and not value.endswith("\n")):
        raise WorkerAuthError("Worker credential must contain exactly one line")
    token = value.rstrip("\n")
    if not 32 <= len(token) <= 512:
        raise WorkerAuthError("Worker credential has an invalid length")
    return token


def read_worker_token(hostname: str) -> str:
    """Read the token issued to a validated worker hostname."""
    hostname = validate_worker_hostname(hostname)
    return read_token_file(_token_dir() / f"{hostname}.token")


def verify_worker_bearer(hostname: str, authorization: str | None) -> None:
    """Verify a bearer credential against the token issued to ``hostname``."""
    if not authorization:
        raise WorkerAuthError("Missing Authorization header")
    parts = authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise WorkerAuthError("Invalid Authorization header")
    expected = read_worker_token(hostname)
    if not hmac.compare_digest(parts[1], expected):
        raise WorkerAuthError("Invalid bearer token")
