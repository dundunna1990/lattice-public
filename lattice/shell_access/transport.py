"""Security policy and OpenSSH client configuration for the Lattice shell channel."""
from __future__ import annotations

from pathlib import Path
import re

from lattice.file_access.keys import validate_ed25519_public_key
from lattice.file_access.manifest import normalize_manifest
from lattice.file_access.transport import host_key_alias

DEFAULT_SHELL_PORT = 22023
DEFAULT_SHELL_DIR = Path("/etc/lattice/shell-ssh")
DEFAULT_HOST_KEY = DEFAULT_SHELL_DIR / "host_ed25519"
DEFAULT_AUTHORIZED_KEYS = Path("/run/lattice-shell-server/authorized_keys")
DEFAULT_KNOWN_HOSTS = DEFAULT_SHELL_DIR / "known_hosts"
DEFAULT_PID_FILE = Path("/run/lattice-shell-sshd/sshd.pid")
DEFAULT_CONTROL_DIR = Path("/run/lattice-shell-control")
PRIVATE_LAN_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

class ShellTransportError(RuntimeError):
    pass


def _key(value: str) -> str:
    fields = validate_ed25519_public_key(value).split()
    return f"{fields[0]} {fields[1]}"


def _peers(manifest_payload: object, local_node_id: str) -> list[dict]:
    manifest = normalize_manifest(manifest_payload)
    if local_node_id not in {m["node_id"] for m in manifest["members"]}:
        raise ShellTransportError("Local computer is not active in this fleet generation")
    return [m for m in manifest["members"] if m["node_id"] != local_node_id]


def render_authorized_keys(manifest_payload: object, local_node_id: str) -> str:
    lines=[]
    for peer in _peers(manifest_payload, local_node_id):
        key=peer.get("shell_public_key")
        if not key:
            continue
        restrictions=(f'from="{",".join(PRIVATE_LAN_CIDRS)}",'
                      'no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc')
        lines.append(f'{restrictions} {_key(key)} lattice-shell-node={peer["node_id"]}')
        next_key = peer.get("shell_next_public_key")
        if next_key:
            lines.append(f'{restrictions} {_key(next_key)} lattice-shell-node={peer["node_id"]}-next')
    return "\n".join(lines) + ("\n" if lines else "")


def render_known_hosts(manifest_payload: object, local_node_id: str) -> str:
    lines=[]
    for peer in _peers(manifest_payload, local_node_id):
        key=peer.get("shell_host_public_key")
        if key:
            lines.append(f'{host_key_alias(peer["node_id"])} {_key(key)}')
        next_key = peer.get("shell_next_host_public_key")
        if next_key:
            lines.append(f'{host_key_alias(peer["node_id"])} {_key(next_key)}')
    return "\n".join(lines) + ("\n" if lines else "")


def render_sshd_config(*, main_user: str, port: int = DEFAULT_SHELL_PORT) -> str:
    if not _USER_RE.fullmatch(main_user) or main_user in {"root", "lattice"}:
        raise ShellTransportError("Shell transport main user is invalid")
    if not 1 <= int(port) <= 65535:
        raise ShellTransportError("Shell transport port is invalid")
    return "\n".join([
        "# Managed by Lattice. Do not edit manually.", f"Port {port}",
        "AddressFamily inet", "ListenAddress 0.0.0.0",
        f"HostKey {DEFAULT_HOST_KEY}", f"PidFile {DEFAULT_PID_FILE}",
        "PubkeyAuthentication yes", "AuthenticationMethods publickey",
        f"AuthorizedKeysFile {DEFAULT_AUTHORIZED_KEYS}", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PermitEmptyPasswords no", "PermitRootLogin no",
        # This is a dedicated key-only fleet SSH daemon.  Keeping PAM enabled can
        # move authenticated sessions into logind scopes outside this service cgroup.
        # Those sessions can then survive a service restart and retain a deleted
        # systemd PrivateTmp namespace.  Keep them in the sshd service cgroup so a
        # restart reliably tears down every old ControlMaster session.
        f"AllowUsers {main_user}", "StrictModes yes", "UsePAM no", "UseDNS no",
        "AllowAgentForwarding no", "AllowTcpForwarding no", "GatewayPorts no",
        "PermitTunnel no", "PermitTTY yes", "X11Forwarding no", "PermitUserEnvironment no",
        "PermitUserRC no", "LoginGraceTime 20", "MaxAuthTries 3", "MaxSessions 32",
        "ClientAliveInterval 30", "ClientAliveCountMax 2", "LogLevel VERBOSE",
        "Subsystem sftp internal-sftp", ""
    ])


def ssh_client_options(*, peer_node_id: str, client_key: Path, known_hosts: Path = DEFAULT_KNOWN_HOSTS, port: int = DEFAULT_SHELL_PORT, control_path: Path | None = None) -> list[str]:
    options=["-p",str(port),"-i",str(client_key),"-o","BatchMode=yes","-o","IdentitiesOnly=yes",
             "-o","NumberOfPasswordPrompts=0","-o","StrictHostKeyChecking=yes","-o",f"UserKnownHostsFile={known_hosts}",
             "-o","GlobalKnownHostsFile=/dev/null","-o",f"HostKeyAlias={host_key_alias(peer_node_id)}",
             "-o","ConnectTimeout=5","-o","ConnectionAttempts=1","-o","ServerAliveInterval=10","-o","ServerAliveCountMax=2"]
    if control_path is not None:
        options += ["-o","ControlMaster=auto","-o","ControlPersist=yes","-o",f"ControlPath={control_path}"]
    return options
