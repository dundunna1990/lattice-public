"""Safe worker-management commands.

Manual-IP enrollment is intentionally absent. A worker must first be a real,
reachable Lattice worker in waiting mode, and privileged credential enrollment
requires explicit local approval of one exact pending request on that worker.
"""

from lattice.core.db import get_db_connection
from lattice.core.mdns import discover_waiting_workers
from lattice.wizard.lifecycle import current_role
from lattice.pairing import pair_worker, repair_worker_network_assignment
import time
import os
import subprocess


def _wake_shell_manager_after_membership_change(*, output=print) -> bool:
    """Wake the existing root shell manager after fleet state + plan are durable."""
    from lattice.core.config import load_config

    try:
        if not load_config().shell_access.enabled:
            return True
        result = subprocess.run(
            [
                "systemctl",
                "kill",
                "--kill-who=main",
                "--signal=SIGUSR1",
                "lattice-shell-connection-manager.service",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        output(
            "Worker was revoked, but immediate trusted-shell cleanup "
            f"could not be requested: {exc}"
        )
        return False

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemd error").strip()
        output(
            "Worker was revoked, but immediate trusted-shell cleanup "
            f"could not be requested: {detail}"
        )
        return False
    return True


def remove_worker_safely(hostname: str, *, ask_confirmation: bool = True, output=print) -> int:
    """Revoke one worker locally, verify it, then remove only master records."""
    try:
        role = current_role()
    except Exception:
        role = None
    if role != "master":
        output("REFUSED: Worker removal is available only on the Lattice Master.")
        return 1
    if ask_confirmation and input(f"Remove worker '{hostname}'? (y/N): ").strip().lower() != "y":
        output("Cancelled.")
        return 0
    conn = get_db_connection()
    try:
        worker = conn.execute(
            "SELECT id, ip FROM workers WHERE hostname = ? AND removed_at IS NULL",
            (hostname,),
        ).fetchone()
        if not worker:
            output(f"Worker {hostname} not found.")
            return 1
        worker_id = int(worker[0])
        worker_ip = worker[1]
        fleet = conn.execute(
            "SELECT node_id, membership_state FROM fleet_nodes WHERE worker_id = ? "
            "ORDER BY CASE membership_state WHEN 'active' THEN 0 ELSE 1 END LIMIT 1",
            (worker_id,),
        ).fetchone()
        if fleet is None or fleet[1] != "active":
            output("Worker has no active signed fleet identity; refusing partial removal.")
            return 1
        target_node_id = str(fleet[0])
        if conn.execute("SELECT 1 FROM fleet_pending_updates LIMIT 1").fetchone() is not None:
            output("Another fleet membership update is pending; finish it before removing a worker.")
            return 1
    finally:
        conn.close()
    from lattice.core.http_client import LatticeHTTPClient
    import asyncio

    port = __import__(
        "lattice.core.config",
        fromlist=["load_config"],
    ).load_config().wire_format.port

    async def _revoke_and_verify():
        client = LatticeHTTPClient(hostname)
        try:
            response = await client.post(
                f"http://{worker_ip}:{port}/v1/pairing/revoke",
                timeout=15,
            )
            if response.status_code != 202:
                return (
                    False,
                    "The worker refused credential revocation. Nothing was removed.",
                )

            revoked = False
            for _ in range(15):
                status = await client.get(
                    f"http://{worker_ip}:{port}/v1/pairing/status",
                    timeout=5,
                )
                if status.status_code == 404:
                    revoked = True
                    break
                await asyncio.sleep(1)

            if not revoked:
                return (
                    False,
                    "The worker did not verify local credential removal. "
                    "Master records were preserved.",
                )
            return True, ""
        except Exception as exc:
            return (
                False,
                f"Could not verify worker credential removal: {exc}",
            )
        finally:
            await client.aclose()

    ok, error = asyncio.run(_revoke_and_verify())
    if not ok:
        output(error)
        return 1

    from lattice.file_access.activation import (
        FleetActivationError,
        revoke_worker_membership,
    )
    from lattice.file_access.transport_queue import (
        FileTransportQueueError,
        queue_transport_reconcile,
    )
    from lattice.file_access.mount_plan import (
        MountPlanError,
        build_mount_plan,
        write_mount_plan,
    )

    conn = get_db_connection()
    candidate = None
    try:
        candidate = revoke_worker_membership(conn, target_node_id=target_node_id)
        result = conn.execute(
            "UPDATE workers SET removed_at = datetime('now') WHERE id = ? AND removed_at IS NULL",
            (worker_id,),
        )
        if result.rowcount != 1:
            raise FleetActivationError("Worker record changed during revocation")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # The signed revocation is already durable. Refresh local file authorization
    # and the trust-bound locator plan before waking shell reconciliation; this
    # ordering prevents the shell manager from seeing a new manifest with an old
    # peer plan.
    try:
        queue_transport_reconcile(candidate.manifest, candidate.signature)
        conn = get_db_connection()
        try:
            rows = conn.execute(
                """SELECT fn.node_id, COALESCE(w.ip, fn.last_known_ip) AS ip
                   FROM fleet_nodes fn LEFT JOIN workers w ON w.id=fn.worker_id
                   WHERE fn.membership_state='active'"""
            ).fetchall()
            locators = {row[0]: row[1] for row in rows if row[1]}
        finally:
            conn.close()
        plan = build_mount_plan(candidate.manifest, locators)
        write_mount_plan(candidate.manifest, plan)
    except (FileTransportQueueError, MountPlanError, OSError) as exc:
        output(
            "Worker was cryptographically revoked, but local reconciliation "
            f"needs attention: {exc}"
        )
        return 1

    if not _wake_shell_manager_after_membership_change(output=output):
        return 1

    if result.rowcount:
        from pathlib import Path
        Path(f"/etc/lattice/tokens/{hostname}.token").unlink(missing_ok=True)
        Path(f"/etc/lattice/worker-certs/{hostname}.crt").unlink(missing_ok=True)
        output(f"Worker '{hostname}' securely revoked and removed.")
        return 0
    output(f"Worker {hostname} not found.")
    return 1


def _add_waiting_worker() -> int:
    if current_role() != "master":
        print("Only a configured Lattice master can look for workers.")
        return 1
    try:
        workers = discover_waiting_workers()
    except Exception as exc:
        print(f"Could not discover waiting workers: {exc}")
        return 1
    if not workers:
        print("No reachable waiting workers found. Finish Worker setup first.")
        return 0
    print("Reachable workers waiting for safe enrollment:")
    for index, worker in enumerate(workers, 1):
        txt = worker.get("txt", {})
        hostname = txt.get("hostname", worker.get("host", "unknown"))
        print(f"  {index}. {hostname} ({worker['addr']})")
    try:
        selected = int(input("Choose a worker number (or press Enter to cancel): ").strip() or "0")
    except ValueError:
        selected = 0
    if selected < 1 or selected > len(workers):
        print("Cancelled.")
        return 0
    worker = workers[selected - 1]
    txt = worker.get("txt", {})
    hostname = txt.get("hostname", worker.get("host", "unknown"))
    code = input(f"Enter the pairing code shown on {hostname}: ").strip()
    if not code:
        print("Cancelled. The pairing code is required.")
        return 0
    print("Request sent. On the worker, approve it locally (or press A in its setup screen).")
    try:
        result = pair_worker(
            hostname=hostname,
            worker_ip=worker["addr"],
            pairing_id=txt["pairing_id"],
            code=code,
        )
    except (KeyError, ValueError) as exc:
        print(f"This discovery record is incomplete: {exc}")
        return 1
    except Exception as exc:
        print(f"Could not pair {hostname}: {exc}")
        return 1
    print(f"Worker '{result['hostname']}' securely paired at {result['ip']}.")
    return 0


def cmd_workers(args) -> int:
    action = args.action
    if action == "list":
        if os.geteuid() != 0:
            from lattice.operator_client import request
            rows = request("workers.list")
            print(f"{'Hostname':<20} {'Status':<12} {'Last Heartbeat':<30}")
            for row in rows:
                print(f"{row['hostname']:<20} {row['status']:<12} {row['last_heartbeat_at'] or 'never':<30}")
            return 0
        conn = get_db_connection()
        try:
            rows = conn.execute(
                "SELECT hostname, status, last_heartbeat_at FROM workers WHERE removed_at IS NULL"
            ).fetchall()
        finally:
            conn.close()
        print(f"{'Hostname':<20} {'Status':<12} {'Last Heartbeat':<30}")
        for row in rows:
            print(f"{row[0]:<20} {row[1]:<12} {row[2] or 'never':<30}")
        return 0

    if action == "get":
        if not args.hostname:
            print("Please specify a hostname.")
            return 1
        if os.geteuid() != 0:
            from lattice.operator_client import request
            row = request("workers.get", {"hostname": args.hostname})
            if row:
                print(
                    f"Hostname: {row['hostname']}\nStatus: {row['status']}\nIP: {row['ip']}"
                    f"\nSSH User: {row['ssh_user']}\nLast Heartbeat: {row['last_heartbeat_at'] or 'never'}"
                )
                return 0
            print(f"Worker {args.hostname} not found.")
            return 1
        conn = get_db_connection()
        try:
            row = conn.execute(
                """
                SELECT hostname, status, ip, ssh_user, last_heartbeat_at
                FROM workers WHERE hostname = ? AND removed_at IS NULL
                """,
                (args.hostname,),
            ).fetchone()
        finally:
            conn.close()
        if row:
            print(
                f"Hostname: {row[0]}\nStatus: {row[1]}\nIP: {row[2]}"
                f"\nSSH User: {row[3]}\nLast Heartbeat: {row[4] or 'never'}"
            )
            return 0
        print(f"Worker {args.hostname} not found.")
        return 1

    if action == "recheck":
        if not args.hostname:
            print("Please specify a hostname.")
            return 1
        conn = get_db_connection()
        try:
            row = conn.execute(
                "SELECT id FROM workers WHERE hostname = ? AND removed_at IS NULL",
                (args.hostname,),
            ).fetchone()
        finally:
            conn.close()
        if not row:
            print(f"Worker {args.hostname} not found.")
            return 1
        from lattice.core.config import set_config_value
        set_config_value(f"health.recheck.{row[0]}", "true")
        print(f"Immediate recheck requested for {args.hostname}.")
        return 0

    if action == "repair-network":
        if not args.hostname:
            print("Please specify a hostname.")
            return 1
        if current_role() != "master":
            print("Only the configured Lattice master can repair a worker network assignment.")
            return 1
        try:
            result = repair_worker_network_assignment(args.hostname)
        except Exception as exc:
            print(f"Could not repair {args.hostname} network assignment: {exc}")
            return 1
        print(
            f"Worker '{result['hostname']}' network assignment completed: "
            f"{result['old_ip']} -> {result['ip']}."
        )
        return 0

    if action == "remove":
        if not args.hostname:
            print("Please specify a hostname.")
            return 1
        return remove_worker_safely(args.hostname)

    if action == "add":
        return _add_waiting_worker()

    print(f"Unknown worker action: {action}")
    return 1
