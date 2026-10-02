"""Fail-closed reconciliation for Lattice's dedicated full-shell SSH channel."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import sqlite3
import tempfile

from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.file_access.identity import load_node_identity
from lattice.file_access.manifest import normalize_manifest
from lattice.file_access.mount_plan import mount_plan_path, validate_mount_plan
from lattice.file_access.sync import get_cached_signed_manifest
from lattice.shell_access.keys import ensure_shell_client_identity, ensure_shell_host_identity
from lattice.shell_access.state import selected_ip
from lattice.shell_access.transport import render_authorized_keys, render_known_hosts, render_sshd_config

SHELL_DIR = Path("/etc/lattice/shell-ssh")
SHELL_CLIENT_RUNTIME_DIR = Path("/run/lattice-shell-client")
SHELL_SERVER_RUNTIME_DIR = Path("/run/lattice-shell-server")
SSH_CONFIG = Path("/etc/ssh/ssh_config.d/90-lattice-shell.conf")
SUDOERS = Path("/etc/sudoers.d/lattice-shell-admin")

class ShellReconcileError(RuntimeError):
    pass


def teardown_shell_channel() -> bool:
    """Remove only Lattice-managed authorization artifacts for a disabled shell channel."""
    changed = False
    managed = (
        SHELL_DIR / "authorized_keys",
        SHELL_DIR / "known_hosts",
        SHELL_DIR / "sshd_config",
        SHELL_SERVER_RUNTIME_DIR / "authorized_keys",
        SHELL_CLIENT_RUNTIME_DIR / "client_ed25519",
        SHELL_CLIENT_RUNTIME_DIR / "known_hosts",
        SSH_CONFIG,
        SUDOERS,
    )
    for path in managed:
        if path.exists() or path.is_symlink():
            if path.is_dir() and not path.is_symlink():
                raise ShellReconcileError(f"Refusing to remove unexpected directory at {path}")
            path.unlink()
            changed = True
    return changed


def _atomic(path: Path, content: str, mode: int) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == content and (path.stat().st_mode & 0o777) == mode:
            return False
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        pass
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as h:
            os.fchmod(h.fileno(), mode)
            h.write(content)
            h.flush(); os.fsync(h.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
        return True
    except Exception:
        Path(tmp).unlink(missing_ok=True)
        raise



def _write_validated_sudoers(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == content and (path.stat().st_mode & 0o777) == 0o440:
            return False
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        pass
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o440)
            handle.write(content)
            handle.flush(); os.fsync(handle.fileno())
        checked = __import__("subprocess").run(
            ["visudo", "-c", "-f", str(temporary)],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if checked.returncode != 0:
            detail=(checked.stderr or checked.stdout or "visudo rejected generated rule").strip()
            raise ShellReconcileError(f"Generated shell sudo policy is invalid: {detail}")
        os.replace(temporary, path)
        os.chmod(path, 0o440)
        return True
    except Exception:
        temporary.unlink(missing_ok=True)
        raise

def _load_manifest() -> dict:
    try:
        cached = get_cached_signed_manifest()
    except Exception:
        cached = None
    if cached is not None:
        return cached[0]
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT manifest FROM fleet_state WHERE id=1").fetchone()
    finally:
        conn.close()
    if row is None:
        raise ShellReconcileError("No trusted fleet manifest is available")
    return normalize_manifest(json.loads(row[0]))


def _load_plan(manifest: dict) -> dict:
    path = mount_plan_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ShellReconcileError(f"Trusted peer locator plan is unavailable: {exc}") from exc
    return validate_mount_plan(manifest, raw)


def _render_client_config(
    manifest: dict, plan: dict, local_node_id: str, main_user: str, port: int,
    preferred_ips: dict[str, str] | None = None,
) -> str:
    members = {m["node_id"]: m for m in manifest["members"]}
    preferred_ips = preferred_ips or {}
    blocks = ["# Managed by Lattice. Do not edit manually."]
    for peer in plan["peers"]:
        if peer["node_id"] == local_node_id:
            continue
        member = members.get(peer["node_id"])
        if not member or not member.get("shell_host_public_key"):
            continue
        hostname = member["hostname"]
        allowed_ips = {str(peer["ip"])}
        allowed_ips.update(
            str(route.get("ip"))
            for route in peer.get("routes", [])
            if isinstance(route, dict) and route.get("ip")
        )
        preferred_ip = preferred_ips.get(str(peer["node_id"]))
        host_ip = preferred_ip if preferred_ip in allowed_ips else str(peer["ip"])
        blocks.extend([
            f"Host {hostname}",
            f"    HostName {host_ip}",
            f"    User {member['main_user']}",
            f"    Port {port}",
            "    BatchMode yes",
            "    IdentitiesOnly yes",
            "    IdentityFile /run/lattice-shell-client/client_ed25519",
            "    StrictHostKeyChecking yes",
            "    UserKnownHostsFile /run/lattice-shell-client/known_hosts",
            "    GlobalKnownHostsFile /dev/null",
            f"    HostKeyAlias lattice-node-{peer['node_id']}",
            "    ConnectTimeout 5",
            "    ServerAliveInterval 10",
            "    ServerAliveCountMax 2",
            "    ControlMaster auto",
            "    ControlPersist yes",
            f"    ControlPath /run/lattice-shell-control/{main_user}-{peer['node_id']}.sock",
            "",
        ])
    return "\n".join(blocks) + "\n"


def reconcile_shell_channel() -> dict[str, object]:
    if os.geteuid() != 0:
        raise ShellReconcileError("Shell channel reconciliation requires root")
    identity = load_node_identity()
    if identity is None:
        raise ShellReconcileError("Permanent node identity is missing")
    config = load_config()
    if not config.shell_access.enabled:
        changed = teardown_shell_channel()
        return {"enabled": False, "changed": changed, "peers": 0, "peer_plans": []}
    manifest = _load_manifest()
    local = next((m for m in manifest["members"] if m["node_id"] == identity.node_id), None)
    if local is None:
        raise ShellReconcileError("This computer is not active in the signed fleet")
    if not local.get("shell_public_key") or not local.get("shell_host_public_key"):
        raise ShellReconcileError("Signed fleet generation does not contain shell identity")
    plan = _load_plan(manifest)
    client = ensure_shell_client_identity()
    host = ensure_shell_host_identity()
    client_identity = client.public_key_text.split()[:2]
    host_identity = host.public_key_text.split()[:2]
    allowed_clients = [local["shell_public_key"].split()[:2]]
    allowed_hosts = [local["shell_host_public_key"].split()[:2]]
    if local.get("shell_next_public_key"):
        allowed_clients.append(local["shell_next_public_key"].split()[:2])
    if local.get("shell_next_host_public_key"):
        allowed_hosts.append(local["shell_next_host_public_key"].split()[:2])
    if client_identity not in allowed_clients:
        raise ShellReconcileError("Local shell client key does not match signed membership or signed rollover")
    if host_identity not in allowed_hosts:
        raise ShellReconcileError("Local shell host key does not match signed membership or signed rollover")

    account = pwd.getpwnam(identity.main_user)
    SHELL_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chown(SHELL_DIR, 0, 0)
    os.chmod(SHELL_DIR, 0o755)
    # Keep canonical shell key material root-owned under /etc/lattice.
    # The normal account cannot traverse /etc/lattice by design, so publish
    # only the client-side material it needs into a private runtime directory.
    os.chown(client.private_key, 0, 0)
    os.chmod(client.private_key, 0o600)
    os.chown(client.public_key, 0, 0)
    os.chmod(client.public_key, 0o644)
    os.chown(host.private_key, 0, 0)
    os.chmod(host.private_key, 0o600)
    changed = False
    authorized_path = SHELL_DIR / "authorized_keys"
    known_hosts_path = SHELL_DIR / "known_hosts"
    changed |= _atomic(authorized_path, render_authorized_keys(manifest, identity.node_id), 0o640)
    os.chown(authorized_path, 0, account.pw_gid)
    os.chmod(authorized_path, 0o640)

    SHELL_SERVER_RUNTIME_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
    os.chown(SHELL_SERVER_RUNTIME_DIR, 0, 0)
    os.chmod(SHELL_SERVER_RUNTIME_DIR, 0o755)
    runtime_authorized = SHELL_SERVER_RUNTIME_DIR / "authorized_keys"
    changed |= _atomic(runtime_authorized, authorized_path.read_text(encoding="utf-8"), 0o640)
    os.chown(runtime_authorized, 0, account.pw_gid)
    os.chmod(runtime_authorized, 0o640)
    changed |= _atomic(known_hosts_path, render_known_hosts(manifest, identity.node_id), 0o640)
    os.chown(known_hosts_path, 0, account.pw_gid)
    os.chmod(known_hosts_path, 0o640)

    SHELL_CLIENT_RUNTIME_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(SHELL_CLIENT_RUNTIME_DIR, account.pw_uid, account.pw_gid)
    os.chmod(SHELL_CLIENT_RUNTIME_DIR, 0o700)
    runtime_client_key = SHELL_CLIENT_RUNTIME_DIR / "client_ed25519"
    runtime_known_hosts = SHELL_CLIENT_RUNTIME_DIR / "known_hosts"
    changed |= _atomic(runtime_client_key, client.private_key.read_text(encoding="utf-8"), 0o600)
    os.chown(runtime_client_key, account.pw_uid, account.pw_gid)
    os.chmod(runtime_client_key, 0o600)
    changed |= _atomic(runtime_known_hosts, known_hosts_path.read_text(encoding="utf-8"), 0o600)
    os.chown(runtime_known_hosts, account.pw_uid, account.pw_gid)
    os.chmod(runtime_known_hosts, 0o600)

    changed |= _atomic(SHELL_DIR / "sshd_config", render_sshd_config(main_user=identity.main_user, port=config.shell_access.port), 0o600)
    preferred_ips = {}
    for peer in plan["peers"]:
        peer_node_id = str(peer.get("node_id", ""))
        if peer_node_id and peer_node_id != identity.node_id:
            remembered = selected_ip(peer_node_id)
            if remembered:
                preferred_ips[peer_node_id] = remembered
    changed |= _atomic(
        SSH_CONFIG,
        _render_client_config(
            manifest, plan, identity.node_id, identity.main_user,
            config.shell_access.port, preferred_ips,
        ),
        0o644,
    )

    # Requirement: the normal main account can perform unattended admin work over
    # this cryptographically restricted fleet-only channel.  Direct root SSH stays disabled.
    sudo_rule = f"{identity.main_user} ALL=(ALL:ALL) NOPASSWD: ALL\n"
    changed |= _write_validated_sudoers(SUDOERS, sudo_rule)
    peer_plans = [dict(peer) for peer in plan["peers"] if peer["node_id"] != identity.node_id]
    return {
        "enabled": True, "changed": changed, "peers": len(peer_plans),
        "peer_plans": peer_plans, "generation": int(manifest["generation"]),
    }


if __name__ == "__main__":
    reconcile_shell_channel()
