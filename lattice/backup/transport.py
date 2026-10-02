"""Restricted SSH/SFTP configuration for remote backup repositories."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import re
import uuid

from lattice.file_access.keys import validate_ed25519_public_key

DEFAULT_BACKUP_PORT = 22024
DEFAULT_BACKUP_DIR = Path("/etc/lattice/backup-ssh")
DEFAULT_HOST_KEY = DEFAULT_BACKUP_DIR / "host_ed25519"
DEFAULT_AUTHORIZED_KEYS_DIR = Path("/etc/lattice-backup-authorized-keys")
DEFAULT_CHROOT_ROOT = Path("/srv/lattice-backup-chroot")
DEFAULT_PID_FILE = Path("/run/lattice-backup-sshd/sshd.pid")
_ACCOUNT_RE = re.compile(r"^lattice-bkp-[0-9a-f]{20}$")


class BackupTransportError(RuntimeError):
    pass


def backup_account_name(source_node_id: str, target_uuid: str) -> str:
    values = []
    for value, label in ((source_node_id, "source Node ID"), (target_uuid, "target ID")):
        try:
            parsed = uuid.UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise BackupTransportError(f"Backup {label} is invalid") from exc
        if parsed.version != 4:
            raise BackupTransportError(f"Backup {label} must be UUIDv4")
        values.append(str(parsed))
    digest = hashlib.sha256(f"{values[0]}:{values[1]}".encode("ascii")).hexdigest()[:20]
    return f"lattice-bkp-{digest}"



@dataclass(frozen=True)
class BackupTransportAccount:
    source_node_id: str
    target_uuid: str
    public_key: str

    @property
    def username(self) -> str:
        return backup_account_name(self.source_node_id, self.target_uuid)


def render_authorized_key(public_key: str) -> str:
    key = validate_ed25519_public_key(public_key)
    return f"restrict {key}\n"


def render_sshd_config(
    accounts: list[BackupTransportAccount],
    *,
    port: int = DEFAULT_BACKUP_PORT,
    host_key: Path = DEFAULT_HOST_KEY,
    authorized_keys_dir: Path = DEFAULT_AUTHORIZED_KEYS_DIR,
    chroot_root: Path = DEFAULT_CHROOT_ROOT,
    pid_file: Path = DEFAULT_PID_FILE,
) -> str:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BackupTransportError("Backup SSH port is invalid")
    if not accounts:
        raise BackupTransportError("Backup SSH transport requires at least one authorized source")
    usernames: list[str] = []
    seen: set[str] = set()
    for account in accounts:
        username = account.username
        if not _ACCOUNT_RE.fullmatch(username) or username in seen:
            raise BackupTransportError("Backup transport account is invalid or duplicated")
        validate_ed25519_public_key(account.public_key)
        seen.add(username)
        usernames.append(username)
    paths = [Path(value) for value in (host_key, authorized_keys_dir, chroot_root, pid_file)]
    if any(not value.is_absolute() for value in paths):
        raise BackupTransportError("Backup transport paths must be absolute")
    lines = [
        "# Managed by Lattice. Do not edit manually.",
        f"Port {port}",
        "AddressFamily any",
        "ListenAddress 0.0.0.0",
        "ListenAddress ::",
        f"HostKey {host_key}",
        f"PidFile {pid_file}",
        "PubkeyAuthentication yes",
        "AuthenticationMethods publickey",
        f"AuthorizedKeysFile {authorized_keys_dir}/%u",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "PermitEmptyPasswords no",
        "PermitRootLogin no",
        "StrictModes yes",
        "UsePAM yes",
        "UseDNS no",
        "DisableForwarding yes",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "GatewayPorts no",
        "PermitTunnel no",
        "PermitTTY no",
        "X11Forwarding no",
        "PermitUserEnvironment no",
        "PermitUserRC no",
        "LogLevel VERBOSE",
        "Subsystem sftp internal-sftp",
        f"AllowUsers {' '.join(usernames)}",
        "",
    ]
    for username in usernames:
        lines.extend([
            f"Match User {username}",
            f"    ChrootDirectory {chroot_root}/{username}",
            "    ForceCommand internal-sftp -d /",
            "    DisableForwarding yes",
            "    PermitTTY no",
            "",
        ])
    return "\n".join(lines)


def backup_host_alias(target_node_id: str) -> str:
    try:
        parsed = uuid.UUID(str(target_node_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise BackupTransportError("Backup target Node ID is invalid") from exc
    if parsed.version != 4:
        raise BackupTransportError("Backup target Node ID must be UUIDv4")
    return f"lattice-backup-node-{parsed}"


def render_known_host(target_node_id: str, host_public_key: str) -> str:
    key = validate_ed25519_public_key(host_public_key)
    return f"{backup_host_alias(target_node_id)} {' '.join(key.split()[:2])}\n"


def restic_sftp_connection(
    *,
    source_node_id: str,
    target_uuid: str,
    target_node_id: str,
    host: str,
    client_key: Path,
    known_hosts: Path,
    port: int = DEFAULT_BACKUP_PORT,
) -> tuple[str, tuple[str, ...]]:
    """Return a chroot-relative Restic SFTP repository and strict SSH args."""
    if not isinstance(host, str) or not host or len(host) > 253:
        raise BackupTransportError("Backup target host is invalid")
    if any(ch.isspace() or ch in "'\"`$;|&<>" for ch in host):
        raise BackupTransportError("Backup target host contains unsafe characters")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise BackupTransportError("Backup SSH port is invalid")
    client_key = Path(client_key)
    known_hosts = Path(known_hosts)
    if not client_key.is_absolute() or not known_hosts.is_absolute():
        raise BackupTransportError("Backup SSH client paths must be absolute")
    username = backup_account_name(source_node_id, target_uuid)
    alias = backup_host_alias(target_node_id)
    repository = f"sftp:{username}@{host}:repo"
    args = (
        "-p", str(port),
        "-i", str(client_key),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"HostKeyAlias={alias}",
        "-o", "ConnectTimeout=10",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=60",
        "-o", "ServerAliveCountMax=240",
    )
    return repository, args
