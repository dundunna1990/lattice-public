"""Strict read-only local operator surface for a Lattice Worker."""
from __future__ import annotations

import socket


class WorkerOperatorRequestError(ValueError):
    """Raised when a Worker operator request is invalid or unsupported."""


def _status() -> dict:
    from lattice.onboarding import get_worker_master_endpoint
    from lattice.worker.health import HealthChecker
    from lattice.file_access.identity import load_node_identity
    from lattice.file_access.sync import get_cached_fleet_generation
    from lattice.file_access.observations import local_mount_observations
    from lattice.file_access.applied_state import (
        FILE_APPLIED_PATH, SHELL_APPLIED_PATH, applied_generation,
    )
    from lattice.core.db import get_db_connection

    identity = load_node_identity()
    endpoint = get_worker_master_endpoint() or {}
    node_id = identity.node_id if identity is not None else None
    conn = get_db_connection()
    try:
        shell_rows = [dict(row) for row in conn.execute(
            "SELECT peer_node_id, hostname, state, selected_ip, failure_count "
            "FROM shell_connection_state ORDER BY hostname, peer_node_id LIMIT 64"
        ).fetchall()]
    finally:
        conn.close()
    return {
        "role": "worker",
        "hostname": socket.gethostname(),
        "node_id": node_id,
        "master_hostname": endpoint.get("hostname"),
        "master_ip": endpoint.get("ip"),
        "master_port": endpoint.get("port"),
        "services": HealthChecker().check_all(),
        "fleet_generation": get_cached_fleet_generation(),
        "file_transport_generation": (
            applied_generation(FILE_APPLIED_PATH, node_id) if node_id else 0
        ),
        "shell_transport_generation": (
            applied_generation(SHELL_APPLIED_PATH, node_id) if node_id else 0
        ),
        "mounts": local_mount_observations(),
        "shell_connections": shell_rows,
    }


def execute_worker_operator_request(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) - {"command", "params"}:
        raise WorkerOperatorRequestError("Operator request must contain only command and params")
    command = payload.get("command")
    params = payload.get("params", {})
    if not isinstance(command, str):
        raise WorkerOperatorRequestError("Operator command is invalid")
    if not isinstance(params, dict) or params:
        raise WorkerOperatorRequestError("Worker operator requests do not accept parameters")
    if command != "status":
        raise WorkerOperatorRequestError(
            "This is a Lattice Worker. Fleet-wide commands are available on the Master."
        )
    return {"ok": True, "command": command, "data": _status()}
