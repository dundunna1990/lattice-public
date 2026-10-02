import sys
import os
import logging
from lattice.cli.tui import get_status

logger = logging.getLogger(__name__)

def cmd_status(args):
    logger.info("Command cmd_status called")

    if os.geteuid() != 0:
        from lattice.operator_client import request
        status = request("status")
        if status.get("role") == "worker":
            return _print_worker_status(status)
        master_hostname = status["master_hostname"]
        master_ip = status["master_ip"]
        workers = status["workers"]
        alerts = status["alerts"]
    else:
        from lattice.wizard.lifecycle import current_role
        if current_role() == "worker":
            from lattice.operator_client import request
            return _print_worker_status(request("status"))
        status = get_status()
        master_hostname = status.master_hostname
        master_ip = status.master_ip
        workers = status.workers
        alerts = status.alerts

    print(f"Master: {master_hostname} ({master_ip})")
    print(f"Workers: {len(workers)}")
    for w in workers:
        print(f"  {w['hostname']}: {w['status']} (last seen: {w['last_seen']})")
    print(f"Alerts: {len(alerts)}")


def _print_worker_status(status):
    print(f"Worker: {status['hostname']}")
    print(f"Node ID: {status.get('node_id') or 'unavailable'}")
    master_name = status.get("master_hostname") or "unknown"
    master_ip = status.get("master_ip") or "unknown"
    print(f"Master: {master_name} ({master_ip})")
    print(f"Fleet generation: {status.get('fleet_generation', 0)}")
    print(f"File transport generation: {status.get('file_transport_generation', 0)}")
    print(f"Shell transport generation: {status.get('shell_transport_generation', 0)}")
    services = status.get("services", [])
    print("Services: " + (", ".join(f"{s.get('name')}: {s.get('status')}" for s in services) or "none"))
    mounts = status.get("mounts", [])
    print("Mounts: " + (", ".join(f"{m.get('peer_node_id')}: {m.get('state')}" for m in mounts) or "none"))
    shells = status.get("shell_connections", [])
    print("Trusted shell: " + (", ".join(f"{s.get('hostname') or s.get('peer_node_id')}: {s.get('state')}" for s in shells) or "none"))
