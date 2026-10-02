"""Maintain persistent ControlMaster SSH sessions to every reachable trusted peer."""
from __future__ import annotations

import logging
import os
from pathlib import Path
import pwd
import signal
import subprocess
import time

from lattice.core.config import load_config
from lattice.file_access.identity import load_node_identity
from lattice.shell_access.reconcile import reconcile_shell_channel
from lattice.shell_access.transport import (
    DEFAULT_KNOWN_HOSTS, DEFAULT_SHELL_DIR, ssh_client_options,
)
from lattice.shell_access.state import (
    mark_connected, mark_retired, mark_unavailable, remembered_routes, selected_ip,
)
from lattice.core.lan_routes import discovered_hostname_ips, merge_candidate_ips
from lattice.file_access.applied_state import (
    SHELL_APPLIED_PATH, record_applied_generation_in_db, write_applied_state,
)
from lattice.shell_access.rotation import (
    cleanup_completed_local_rotation,
    confirm_local_promotion_ready,
    ensure_rotation_staged_if_due,
    finalize_master_rotation,
    process_master_rotation_proposal,
    promote_local_rotation_if_requested,
    record_promote_request,
    rotation_promotion_request_for,
)
from lattice.wizard.lifecycle import current_role

CONTROL_ROOT = Path("/run/lattice-shell-control")
CLIENT_RUNTIME_ROOT = Path("/run/lattice-shell-client")
logger = logging.getLogger(__name__)
_STOP = False
_WAKE = False

def _stop(*_args):
    global _STOP
    _STOP = True

def _wake(*_args):
    """Request an immediate safe reconciliation without touching SSH processes."""
    global _WAKE
    _WAKE = True

def _run_as(uid: int, gid: int, argv: list[str]) -> subprocess.CompletedProcess:
    def demote():
        os.setgid(gid); os.setuid(uid)
    return subprocess.run(argv, capture_output=True, text=True, timeout=15, preexec_fn=demote)

def _socket_path(user: str, node_id: str) -> Path:
    return CONTROL_ROOT / f"{user}-{node_id}.sock"

def reconcile_connections() -> None:
    identity = load_node_identity()
    proposal = ensure_rotation_staged_if_due()
    role = current_role()
    if identity is not None and role == "master" and proposal is not None:
        process_master_rotation_proposal(identity.node_id, proposal)
        request = rotation_promotion_request_for(identity.node_id)
        if request is not None:
            record_promote_request(request)
    promoted = promote_local_rotation_if_requested()
    if promoted is not None:
        restarted = subprocess.run(
            ["systemctl", "restart", "lattice-shell-sshd.service"],
            capture_output=True, text=True, timeout=20,
        )
        if restarted.returncode != 0:
            detail = (restarted.stderr or restarted.stdout or "systemd error").strip()
            raise RuntimeError(f"Could not activate promoted shell host key: {detail}")
        confirm_local_promotion_ready()
        if identity is not None and role == "master":
            finalize_master_rotation(identity.node_id, promoted)
    cleanup_completed_local_rotation()

    result = reconcile_shell_channel()
    if not result.get("enabled"):
        stopped = subprocess.run(
            ["systemctl", "stop", "lattice-shell-sshd.service"],
            capture_output=True, text=True, timeout=20,
        )
        if stopped.returncode != 0:
            detail = (stopped.stderr or stopped.stdout or "systemd error").strip()
            raise RuntimeError(f"Could not stop disabled shell SSH service: {detail}")
        if identity is not None:
            account = pwd.getpwnam(identity.main_user)
            if CONTROL_ROOT.exists():
                for sock in CONTROL_ROOT.glob(f"{identity.main_user}-*.sock"):
                    _run_as(
                        account.pw_uid, account.pw_gid,
                        ["ssh", "-S", str(sock), "-O", "exit", "localhost"],
                    )
                    sock.unlink(missing_ok=True)
        return
    if result.get("changed"):
        restarted = subprocess.run(
            ["systemctl", "restart", "lattice-shell-sshd.service"],
            capture_output=True, text=True, timeout=20,
        )
        if restarted.returncode != 0:
            detail = (restarted.stderr or restarted.stdout or "systemd error").strip()
            raise RuntimeError(f"Could not restart dedicated shell SSH service: {detail}")
    if identity is not None and result.get("generation"):
        write_applied_state(
            SHELL_APPLIED_PATH,
            node_id=identity.node_id,
            generation=int(result["generation"]),
        )
        record_applied_generation_in_db(
            "shell", identity.node_id, int(result["generation"])
        )
    identity = load_node_identity()
    if identity is None:
        return
    account = pwd.getpwnam(identity.main_user)
    CONTROL_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(CONTROL_ROOT, account.pw_uid, account.pw_gid)
    os.chmod(CONTROL_ROOT, 0o700)
    desired: set[Path] = set()
    for peer in result.get("peer_plans", []):
        if peer.get("node_id") == identity.node_id:
            continue
        node_id = str(peer["node_id"])
        host = str(peer["hostname"])
        sock = _socket_path(identity.main_user, node_id)
        desired.add(sock)
        remembered_ip = selected_ip(node_id)
        primary_ip = str(peer["ip"])
        planned_routes = peer.get("routes", [])

        allowed_ips = {primary_ip}
        allowed_ips.update(
            str(route.get("ip"))
            for route in planned_routes
            if isinstance(route, dict)
            and route.get("ip")
        )

        options = ssh_client_options(
            peer_node_id=node_id,
            client_key=CLIENT_RUNTIME_ROOT / "client_ed25519",
            known_hosts=CLIENT_RUNTIME_ROOT / "known_hosts",
            port=load_config().shell_access.port,
        )

        check = _run_as(
            account.pw_uid,
            account.pw_gid,
            [
                "ssh",
                "-S",
                str(sock),
                "-O",
                "check",
                host,
            ],
        )

        if (
            check.returncode == 0
            and remembered_ip
            and remembered_ip in allowed_ips
        ):
            if remembered_ip == primary_ip:
                mark_connected(
                    node_id,
                    host,
                    remembered_ip,
                )
                continue

            # Never let a surviving ControlMaster session prove an
            # old IP healthy. Open a completely fresh SSH connection
            # to the selected alternate route and verify the pinned
            # Node-ID host key.
            fresh = _run_as(
                account.pw_uid,
                account.pw_gid,
                [
                    "ssh",
                    "-o",
                    "ControlMaster=no",
                    "-o",
                    "ControlPath=none",
                    *options,
                    f"{peer['remote_user']}@{remembered_ip}",
                    "true",
                ],
            )

            if fresh.returncode == 0:
                mark_connected(
                    node_id,
                    host,
                    remembered_ip,
                )
                continue

        if check.returncode == 0:
            _run_as(
                account.pw_uid,
                account.pw_gid,
                [
                    "ssh",
                    "-S",
                    str(sock),
                    "-O",
                    "exit",
                    host,
                ],
            )

        sock.unlink(missing_ok=True)

        candidates = merge_candidate_ips(
            planned_routes,
            *remembered_routes(node_id),
            peer.get("ip"),
        )
        for discovered in discovered_hostname_ips(host):
            if discovered not in candidates:
                candidates.append(discovered)

        errors: list[str] = []
        connected_ip = None
        for candidate_ip in candidates:
            opened = _run_as(account.pw_uid, account.pw_gid, [
                "ssh", "-fN", "-M", "-S", str(sock), "-o", "ControlPersist=yes",
                *options, f"{peer['remote_user']}@{candidate_ip}",
            ])
            if opened.returncode == 0:
                connected_ip = candidate_ip
                break
            errors.append((opened.stderr or opened.stdout or "SSH connection failed").strip())
            sock.unlink(missing_ok=True)

        if connected_ip is not None:
            mark_connected(node_id, host, connected_ip)
        else:
            detail = errors[-1] if errors else "No private LAN route is currently available"
            mark_unavailable(node_id, host, candidates, detail)
            logger.warning(
                "Trusted shell connection to %s (%s) is unavailable: %s",
                host, node_id, detail,
            )
    for stale in CONTROL_ROOT.glob(f"{identity.main_user}-*.sock"):
        if stale not in desired:
            node_id = stale.stem.removeprefix(f"{identity.main_user}-")
            try:
                _run_as(account.pw_uid, account.pw_gid, [
                    "ssh", "-S", str(stale), "-O", "exit", "localhost"
                ])
            finally:
                stale.unlink(missing_ok=True)
                mark_retired(node_id, node_id)

def run_forever() -> None:
    global _WAKE
    signal.signal(signal.SIGTERM, _stop); signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGUSR1, _wake)
    while not _STOP:
        try:
            reconcile_connections()
        except Exception as exc:
            logger.exception("Shell connection reconciliation failed: %s", exc)
        delay = max(1, int(load_config().shell_access.reconnect_seconds))
        for _ in range(delay * 2):
            if _STOP:
                break
            if _WAKE:
                _WAKE = False
                break
            time.sleep(0.5)

if __name__ == "__main__":
    run_forever()
