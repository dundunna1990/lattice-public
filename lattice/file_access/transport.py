"""Security policy for Lattice's dedicated SFTP-only file transport."""

from __future__ import annotations

from pathlib import Path
import re
import uuid

from lattice.file_access.keys import (
    validate_ed25519_public_key,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    normalize_manifest,
)


DEFAULT_FILE_PORT = 22022

DEFAULT_HOST_KEY = Path(
    "/etc/lattice/file-ssh/host_ed25519"
)
DEFAULT_AUTHORIZED_KEYS = Path(
    "/etc/lattice/file-ssh/authorized_keys"
)
DEFAULT_RUNTIME_AUTHORIZED_KEYS = Path(
    "/run/lattice-file-sshd/authorized_keys"
)
DEFAULT_KNOWN_HOSTS = Path(
    "/etc/lattice/file-ssh/known_hosts"
)
DEFAULT_CHROOT = Path(
    "/srv/lattice-file-root"
)
DEFAULT_PID_FILE = Path(
    "/run/lattice-file-sshd/sshd.pid"
)

PRIVATE_LAN_CIDRS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
)

_USER_RE = re.compile(
    r"^[a-z_][a-z0-9_-]{0,31}$"
)


class FileTransportError(RuntimeError):
    """Raised when secure file transport policy cannot be constructed."""


def _node_id(value: object) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (
        TypeError,
        ValueError,
        AttributeError,
    ) as exc:
        raise FileTransportError(
            "File transport node ID is invalid"
        ) from exc

    if parsed.version != 4:
        raise FileTransportError(
            "File transport node ID must be UUIDv4"
        )

    return str(parsed)


def _absolute_path(
    value: Path,
    label: str,
) -> Path:
    path = Path(value)

    if (
        not path.is_absolute()
        or "\n" in str(path)
        or "\r" in str(path)
    ):
        raise FileTransportError(
            f"{label} must be a safe absolute path"
        )

    return path


def _key_without_comment(public_key: str) -> str:
    value = validate_ed25519_public_key(
        public_key
    )
    fields = value.split()
    return f"{fields[0]} {fields[1]}"


def host_key_alias(node_id: object) -> str:
    """Stable SSH host lookup name independent of IP and hostname."""
    return f"lattice-node-{_node_id(node_id)}"


def _local_and_peers(
    manifest_payload: object,
    local_node_id: object,
):
    try:
        manifest = normalize_manifest(
            manifest_payload
        )
    except FleetManifestError as exc:
        raise FileTransportError(
            f"Fleet manifest is invalid: {exc}"
        ) from exc

    local_id = _node_id(local_node_id)

    local = next(
        (
            member
            for member in manifest["members"]
            if member["node_id"] == local_id
        ),
        None,
    )

    if local is None:
        raise FileTransportError(
            "Local computer is not active in this fleet generation"
        )

    peers = [
        member
        for member in manifest["members"]
        if member["node_id"] != local_id
    ]

    return manifest, local, peers


def render_authorized_keys(
    manifest_payload: object,
    local_node_id: object,
) -> str:
    """Authorize every other active fleet member for file access."""
    _, _, peers = _local_and_peers(
        manifest_payload,
        local_node_id,
    )

    source_policy = ",".join(
        PRIVATE_LAN_CIDRS
    )

    lines: list[str] = []

    for peer in peers:
        key = _key_without_comment(
            peer["file_public_key"]
        )

        lines.append(
            'restrict,'
            f'from="{source_policy}" '
            f"{key} "
            f"lattice-node={peer['node_id']} "
            f"lattice-host={peer['hostname']}"
        )
        next_key = peer.get("file_next_public_key")
        if next_key:
            lines.append(
                'restrict,'
                f'from="{source_policy}" '
                f"{_key_without_comment(next_key)} "
                f"lattice-node={peer['node_id']}-next "
                f"lattice-host={peer['hostname']}"
            )

    return (
        "\n".join(lines) + "\n"
        if lines
        else ""
    )


def render_known_hosts(
    manifest_payload: object,
    local_node_id: object,
) -> str:
    """Pin every peer host key to immutable Node ID aliases."""
    _, _, peers = _local_and_peers(
        manifest_payload,
        local_node_id,
    )

    lines: list[str] = []

    for peer in peers:
        key = _key_without_comment(
            peer["file_host_public_key"]
        )

        lines.append(
            f"{host_key_alias(peer['node_id'])} "
            f"{key}"
        )
        next_key = peer.get("file_next_host_public_key")
        if next_key:
            lines.append(
                f"{host_key_alias(peer['node_id'])} "
                f"{_key_without_comment(next_key)}"
            )

    return (
        "\n".join(lines) + "\n"
        if lines
        else ""
    )


def render_sshd_config(
    *,
    main_user: str,
    port: int = DEFAULT_FILE_PORT,
    host_key: Path = DEFAULT_HOST_KEY,
    authorized_keys: Path = DEFAULT_RUNTIME_AUTHORIZED_KEYS,
    chroot: Path = DEFAULT_CHROOT,
    pid_file: Path = DEFAULT_PID_FILE,
) -> str:
    """Render the independent SFTP-only sshd configuration."""
    if (
        not isinstance(main_user, str)
        or not _USER_RE.fullmatch(main_user)
        or main_user in {"root", "lattice"}
    ):
        raise FileTransportError(
            "File transport main user is invalid"
        )

    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise FileTransportError(
            "File transport port is invalid"
        )

    host_key = _absolute_path(
        host_key,
        "Host key"
    )
    authorized_keys = _absolute_path(
        authorized_keys,
        "Authorized keys"
    )
    chroot = _absolute_path(
        chroot,
        "Chroot"
    )
    pid_file = _absolute_path(
        pid_file,
        "PID file"
    )

    return "\n".join(
        [
            "# Managed by Lattice. Do not edit manually.",
            f"Port {port}",
            "AddressFamily any",
            "ListenAddress 0.0.0.0",
            "ListenAddress ::",
            f"HostKey {host_key}",
            f"PidFile {pid_file}",
            "",
            "PubkeyAuthentication yes",
            "AuthenticationMethods publickey",
            f"AuthorizedKeysFile {authorized_keys}",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "PermitEmptyPasswords no",
            "PermitRootLogin no",
            "HostbasedAuthentication no",
            "",
            f"AllowUsers {main_user}",
            "StrictModes yes",
            "UsePAM yes",
            "UseDNS no",
            "",
            "DisableForwarding yes",
            "AllowAgentForwarding no",
            "AllowTcpForwarding no",
            "GatewayPorts no",
            "PermitTunnel no",
            "PermitTTY no",
            "X11Forwarding no",
            "PermitUserEnvironment no",
            "PermitUserRC no",
            "",
            "LoginGraceTime 20",
            "MaxAuthTries 3",
            "MaxSessions 16",
            "ClientAliveInterval 30",
            "ClientAliveCountMax 2",
            "LogLevel VERBOSE",
            "",
            "Subsystem sftp internal-sftp",
            f"ChrootDirectory {chroot}",
            "ForceCommand internal-sftp -d /Home",
            "",
        ]
    )


def ssh_client_options(
    *,
    peer_node_id: object,
    client_key: Path,
    known_hosts: Path = DEFAULT_KNOWN_HOSTS,
    port: int = DEFAULT_FILE_PORT,
) -> list[str]:
    """Strict SSH options later consumed by SSHFS/SFTP clients."""
    alias = host_key_alias(
        peer_node_id
    )

    client_key = _absolute_path(
        client_key,
        "Client key"
    )
    known_hosts = _absolute_path(
        known_hosts,
        "Known-hosts file"
    )

    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not 1 <= port <= 65535
    ):
        raise FileTransportError(
            "File transport port is invalid"
        )

    return [
        "-p",
        str(port),
        "-i",
        str(client_key),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        f"HostKeyAlias={alias}",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
    ]
