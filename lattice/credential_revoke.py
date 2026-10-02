"""Durable, root-completed removal of credentials for a locally paired worker."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import grp
import re
import secrets
import stat


REQUEST = Path("/var/lib/lattice/revoke-request.json")
STATE = Path("/var/lib/lattice/pairing.json")
TOKEN_DIR = Path("/etc/lattice/tokens")
MASTER_ENDPOINT = Path("/var/lib/lattice/master-endpoint.json")
MASTER_CA = Path("/etc/lattice/pki/ca.crt")
SUDOERS_DIR = Path("/etc/sudoers.d")
RECOVERY_AUTHORITY = Path("/var/lib/lattice-root/recovery-authority.json")
NETWORK_ASSIGNMENT_AUTHORITY = Path("/var/lib/lattice-root/network-assignment-authority.json")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_read(path: Path, expected_uids: set[int], maximum: int) -> tuple[str, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(path.parent, directory_flags)
    try:
        descriptor = os.open(path.name, flags, dir_fd=directory_fd)
    except Exception:
        os.close(directory_fd)
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError(f"{path} is not a single regular file")
        if metadata.st_uid not in expected_uids or metadata.st_mode & 0o022:
            raise RuntimeError(f"{path} has unsafe ownership or permissions")
        if metadata.st_size > maximum:
            raise RuntimeError(f"{path} is too large")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
        os.close(directory_fd)
    try:
        return raw.decode("utf-8"), metadata
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{path} is not valid UTF-8") from exc


def _atomic_write(path: Path, text: str, mode: int, uid: int, gid: int) -> None:
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(path.parent, directory_flags)
    temporary_name = f".{path.name}.{secrets.token_hex(12)}.tmp"
    descriptor = None
    try:
        try:
            metadata = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None and (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        ):
            raise RuntimeError(f"Refusing to replace unsafe path {path}")
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary_name, flags, mode, dir_fd=directory_fd)
        payload = text.encode("utf-8")
        written = 0
        while written < len(payload):
            written += os.write(descriptor, payload[written:])
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary_name, path.name,
            src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _load_state(lattice_uid: int) -> dict:
    try:
        text, _ = _safe_read(STATE, {lattice_uid}, 32768)
        state = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Pairing state cannot be read safely: {exc}") from exc
    if not isinstance(state, dict):
        raise ValueError("Pairing state has an invalid format")
    return state


def _matching_key(line: str, key_blob: str) -> bool:
    fields = line.split()
    return any(
        fields[index] == "ssh-ed25519" and fields[index + 1] == key_blob
        for index in range(len(fields) - 1)
    )


def _validate_regular_if_present(path: Path, expected_uid: int, maximum: int) -> str | None:
    try:
        text, _ = _safe_read(path, {expected_uid}, maximum)
        return text
    except FileNotFoundError:
        return None


def queue_local_revoke(hostname: str) -> None:
    """Durably authorize root to revoke exactly the current pairing."""
    if not isinstance(hostname, str) or not HOST_RE.fullmatch(hostname):
        raise ValueError("Worker hostname has an invalid format")
    lattice = pwd.getpwnam("lattice")
    lattice_group = grp.getgrnam("lattice")
    state = _load_state(lattice.pw_uid)
    if state.get("state") != "paired" or state.get("hostname") != hostname:
        raise ValueError("This worker is not paired under that name")
    pairing_id = state.get("pairing_id")
    if not isinstance(pairing_id, str) or not pairing_id:
        raise ValueError("Pairing state has no credential generation")
    payload = {
        "hostname": hostname,
        "pairing_id": pairing_id,
        "requested_at": _now().isoformat(),
    }
    if REQUEST.exists() or REQUEST.is_symlink():
        try:
            existing, _ = _safe_read(REQUEST, {lattice.pw_uid, 0}, 4096)
            saved = json.loads(existing)
        except (OSError, RuntimeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Existing revocation request is unsafe: {exc}") from exc
        if saved.get("hostname") == hostname and saved.get("pairing_id") == pairing_id:
            return
        raise RuntimeError("A different credential revocation is already pending")
    _atomic_write(
        REQUEST,
        json.dumps(payload, sort_keys=True) + "\n",
        0o600,
        lattice.pw_uid,
        lattice_group.gr_gid,
    )


def revoke() -> None:
    """Root side of revocation; safe to retry after an interrupted deletion."""
    if os.geteuid() != 0:
        raise RuntimeError("Credential revocation must run as root")
    lattice = pwd.getpwnam("lattice")
    lattice_group = grp.getgrnam("lattice")
    try:
        request_text, _ = _safe_read(REQUEST, {lattice.pw_uid, 0}, 4096)
        request = json.loads(request_text)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Revocation request cannot be read safely: {exc}") from exc
    state = _load_state(lattice.pw_uid)
    if not isinstance(request, dict):
        raise RuntimeError("Revocation request has an invalid format")
    hostname = request.get("hostname")
    pairing_id = request.get("pairing_id")
    if (
        not isinstance(hostname, str)
        or not HOST_RE.fullmatch(hostname)
        or state.get("state") != "paired"
        or state.get("hostname") != hostname
        or state.get("pairing_id") != pairing_id
    ):
        raise RuntimeError("Revocation request does not match the active pairing")
    try:
        requested_at = datetime.fromisoformat(str(request["requested_at"]))
        if requested_at.tzinfo is None:
            raise ValueError("timezone is missing")
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Revocation request has an invalid timestamp") from exc
    age = (_now() - requested_at).total_seconds()
    if age < 0 or age > 300:
        raise RuntimeError("Revocation request has expired")

    ssh_user = state.get("ssh_user")
    key_blob = state.get("master_key_blob")
    if not isinstance(ssh_user, str) or not USER_RE.fullmatch(ssh_user):
        raise RuntimeError("Paired SSH user is invalid")
    if not isinstance(key_blob, str) or not key_blob or any(ch.isspace() for ch in key_blob):
        raise RuntimeError("Paired SSH key identity is invalid")
    account = pwd.getpwnam(ssh_user)
    if account.pw_uid == 0:
        raise RuntimeError("Root cannot be a paired SSH target")
    home = Path(account.pw_dir)
    ssh_dir = home / ".ssh"
    authorized = ssh_dir / "authorized_keys"
    sudoers = SUDOERS_DIR / f"lattice-remote-heal-{ssh_user}"
    token = TOKEN_DIR / f"{hostname}.token"

    # Validate every mutable path before deleting the first credential.  This
    # prevents symlink substitution from turning revocation into arbitrary
    # root file writes/deletes.
    if home.is_symlink() or not home.is_dir() or home.stat().st_uid != account.pw_uid:
        raise RuntimeError("SSH home directory is unsafe")
    if ssh_dir.exists() or ssh_dir.is_symlink():
        metadata = ssh_dir.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != account.pw_uid or metadata.st_mode & 0o022:
            raise RuntimeError("SSH directory is unsafe")
    authorized_text = _validate_regular_if_present(authorized, account.pw_uid, 1024 * 1024)
    _validate_regular_if_present(sudoers, 0, 4096)
    _validate_regular_if_present(token, 0, 1024)
    _validate_regular_if_present(MASTER_ENDPOINT, lattice.pw_uid, 4096)
    _validate_regular_if_present(MASTER_CA, 0, 32768)
    authority_text = _validate_regular_if_present(RECOVERY_AUTHORITY, 0, 16384)
    _validate_regular_if_present(NETWORK_ASSIGNMENT_AUTHORITY, 0, 16384)
    if authority_text is not None:
        try:
            authority = json.loads(authority_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Root recovery authority is invalid JSON") from exc
        if (
            not isinstance(authority, dict)
            or authority.get("pairing_id") != pairing_id
            or authority.get("worker_hostname") != hostname
            or authority.get("ssh_user") != ssh_user
            or authority.get("master_key_blob") != key_blob
        ):
            raise RuntimeError("Root recovery authority does not match the active pairing")

    if authorized_text is not None:
        kept = [
            line for line in authorized_text.splitlines()
            if not _matching_key(line, key_blob)
        ]
        _atomic_write(
            authorized,
            ("\n".join(kept) + "\n") if kept else "",
            0o600,
            account.pw_uid,
            account.pw_gid,
        )
    for path in (
        sudoers, token, MASTER_ENDPOINT, MASTER_CA, RECOVERY_AUTHORITY,
        NETWORK_ASSIGNMENT_AUTHORITY,
    ):
        path.unlink(missing_ok=True)

    tombstone = {
        "state": "revoked",
        "pairing_id": pairing_id,
        "hostname": hostname,
        "ssh_user": ssh_user,
        "revoked_at": _now().isoformat(),
    }
    _atomic_write(
        STATE,
        json.dumps(tombstone, sort_keys=True) + "\n",
        0o600,
        lattice.pw_uid,
        lattice_group.gr_gid,
    )
    REQUEST.unlink()


def revoke_local_pairing() -> None:
    """Let the configured local SSH user revoke a lost or replaced master."""
    if os.geteuid() != 0:
        raise RuntimeError("Local credential revocation requires sudo")
    lattice = pwd.getpwnam("lattice")
    state = _load_state(lattice.pw_uid)
    if state.get("state") != "paired":
        raise RuntimeError("This worker is not currently paired")
    if os.environ.get("SUDO_USER") != state.get("ssh_user"):
        raise RuntimeError("Revocation must be approved by the configured local SSH user")
    queue_local_revoke(str(state.get("hostname", "")))
    revoke()


def revoke_for_uninstall() -> bool:
    """Remove only the currently recorded Lattice pairing during uninstall."""
    if os.geteuid() != 0:
        raise RuntimeError("Uninstall credential cleanup requires root")
    if not STATE.exists() and not STATE.is_symlink():
        return False
    lattice = pwd.getpwnam("lattice")
    # If state exists but is malformed or unsafe, stop uninstall. Continuing
    # could strand a live Lattice credential that we can no longer identify.
    state = _load_state(lattice.pw_uid)
    if state.get("state") != "paired":
        return False
    queue_local_revoke(str(state.get("hostname", "")))
    revoke()
    return True


if __name__ == "__main__":
    if len(__import__("sys").argv) == 2 and __import__("sys").argv[1] == "--uninstall":
        revoke_for_uninstall()
    else:
        revoke()
