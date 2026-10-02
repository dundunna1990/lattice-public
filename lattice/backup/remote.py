"""Resolve signed remote-backup authorization into strict Restic SFTP connections."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from lattice.backup.assignment_state import current_assignment_state
from lattice.backup.keys import DEFAULT_BACKUP_SSH_DIR, ensure_backup_client_identity
from lattice.backup.sync import BackupSyncError, get_cached_signed_backup_assignment
from lattice.backup.transport import render_known_host, restic_sftp_connection
from lattice.file_access.mount_manager import MountManagerError, load_mount_plans
from lattice.shell_access.state import remembered_routes, selected_ip

DEFAULT_KNOWN_HOSTS_DIR = DEFAULT_BACKUP_SSH_DIR / "known-hosts"
DEFAULT_CLIENT_KEY = DEFAULT_BACKUP_SSH_DIR / "client_ed25519"


class RemoteBackupError(RuntimeError):
    pass


@dataclass(frozen=True)
class RemoteConnection:
    host: str
    repository: str
    ssh_args: tuple[str, ...]


def sftp_capacity(
    connection: RemoteConnection,
    *,
    runner=None,
) -> tuple[int, int]:
    """Return total/free bytes for the chrooted repository filesystem."""
    if runner is None:
        runner = subprocess.run
    repository = str(connection.repository)
    if not repository.startswith("sftp:"):
        raise RemoteBackupError("Remote backup repository is not SFTP")
    try:
        user_host, repo_path = repository[len("sftp:"):].rsplit(":", 1)
    except ValueError as exc:
        raise RemoteBackupError("Remote backup repository path is invalid") from exc
    if not user_host or repo_path != "repo":
        raise RemoteBackupError("Remote backup repository path is unexpected")

    args = list(connection.ssh_args)
    if len(args) >= 2 and args[0] == "-p":
        args[0] = "-P"
    command = ["/usr/bin/sftp", "-q", "-b", "-", *args, user_host]
    try:
        result = runner(
            command,
            input="df repo\nquit\n",
            text=True,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RemoteBackupError("Could not query remote backup capacity") from exc
    if result.returncode != 0:
        raise RemoteBackupError("Could not query remote backup capacity")

    for line in (result.stdout or "").splitlines():
        match = re.match(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+%\s*$", line)
        if match:
            total_kib = int(match.group(1))
            available_kib = int(match.group(3))
            if total_kib <= 0 or available_kib < 0:
                break
            return total_kib * 1024, available_kib * 1024
    raise RemoteBackupError("Remote backup capacity response is invalid")


def _private_ipv4(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.version != 4 or not address.is_private:
        return None
    return str(address)


def _local_ipv4_addresses() -> set[str]:
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    addresses: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        value = parts[3].split("/", 1)[0]
        normalized = _private_ipv4(value)
        if normalized:
            addresses.add(normalized)
    return addresses


def target_routes(
    target_node_id: str,
    *,
    local_address_resolver=_local_ipv4_addresses,
) -> list[str]:
    candidates: list[str] = []
    try:
        for plan in load_mount_plans():
            if plan.node_id != target_node_id:
                continue
            candidates.extend([plan.ip, *plan.routes])
            break
    except MountManagerError:
        pass
    try:
        remembered = selected_ip(target_node_id)
        if remembered:
            candidates.append(remembered)
        candidates.extend(remembered_routes(target_node_id))
    except Exception:
        pass
    local_addresses = set(local_address_resolver())
    result: list[str] = []
    for value in candidates:
        normalized = _private_ipv4(str(value))
        if normalized and normalized not in local_addresses and normalized not in result:
            result.append(normalized)
    if not result:
        raise RemoteBackupError("No current private-LAN route is known for the backup target")
    return result


def _signed_assignment() -> dict:
    try:
        cached = get_cached_signed_backup_assignment()
    except BackupSyncError as exc:
        raise RemoteBackupError(str(exc)) from exc
    if cached is not None:
        assignment, signature = cached
        return {"assignment": assignment, "signature": signature}
    state = current_assignment_state()
    if state is None:
        raise RemoteBackupError("No signed backup assignment is available yet")
    return state


def assignment_for_job(job: dict) -> dict:
    state = _signed_assignment()
    items = state["assignment"]["assignments"]
    match = next(
        (
            item for item in items
            if item["source_node_id"] == job["source_node_id"]
            and item["target_node_id"] == job["host_node_id"]
            and item["target_uuid"] == job["target_uuid"]
            and item["repository_id"] == job["job_uuid"]
        ),
        None,
    )
    if match is None:
        raise RemoteBackupError("Backup job is not authorized by the current signed assignment")
    local_client = ensure_backup_client_identity()
    if local_client.public_key_text.split()[:2] != match["backup_public_key"].split()[:2]:
        raise RemoteBackupError("Signed backup assignment contains the wrong local client key")
    return match


def _atomic_known_host(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent == DEFAULT_KNOWN_HOSTS_DIR and os.geteuid() == 0:
        os.chown(path.parent, 0, 0)
        os.chmod(path.parent, 0o700)
    if path.exists() or path.is_symlink():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RemoteBackupError("Backup known-hosts path is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def connection_candidates(
    job: dict,
    *,
    known_hosts_dir: Path = DEFAULT_KNOWN_HOSTS_DIR,
    client_key: Path = DEFAULT_CLIENT_KEY,
    route_resolver=target_routes,
) -> list[RemoteConnection]:
    authorization = assignment_for_job(job)
    known_hosts = Path(known_hosts_dir) / f"{job['host_node_id']}.known_hosts"
    _atomic_known_host(
        known_hosts,
        render_known_host(job["host_node_id"], authorization["backup_host_public_key"]),
    )
    connections = []
    for host in route_resolver(job["host_node_id"]):
        repository, ssh_args = restic_sftp_connection(
            source_node_id=job["source_node_id"],
            target_uuid=job["target_uuid"],
            target_node_id=job["host_node_id"],
            host=host,
            client_key=Path(client_key),
            known_hosts=known_hosts,
        )
        connections.append(RemoteConnection(host, repository, ssh_args))
    return connections
