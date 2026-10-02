"""Operator controls for persistent Lattice peer mounts."""

from __future__ import annotations

import subprocess
import os
import uuid

from lattice.core.db import get_db_connection
from lattice.file_access.mount_manager import (
    MountManagerError,
    set_mount_preference,
)


def _node_id(value: str) -> str:
    try:
        parsed = uuid.UUID(
            value
        )
    except (
        ValueError,
        TypeError,
        AttributeError,
    ) as exc:
        raise MountManagerError(
            "Peer must be an immutable Node ID"
        ) from exc

    if parsed.version != 4:
        raise MountManagerError(
            "Peer Node ID must be UUIDv4"
        )

    return str(parsed)


def _wake_manager() -> None:
    """Best effort: persistent state is already saved if this fails."""
    try:
        subprocess.run(
            [
                "systemctl",
                "kill",
                "--kill-who=main",
                "--signal=SIGUSR1",
                "lattice-mount-manager.service",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        pass


def _rows():
    conn = get_db_connection()

    try:
        return conn.execute(
            """
            SELECT
                ms.peer_node_id,
                fn.hostname,
                COALESCE(
                    mp.desired_state,
                    'mounted'
                ) AS desired_state,
                ms.state,
                ms.mount_path,
                ms.failure_count,
                ms.problem_since,
                ms.error_code,
                ms.error_message
            FROM mount_state AS ms
            LEFT JOIN mount_preferences AS mp
              ON mp.peer_node_id = ms.peer_node_id
            LEFT JOIN fleet_nodes AS fn
              ON fn.node_id = ms.peer_node_id
            ORDER BY
                COALESCE(
                    fn.hostname,
                    ms.peer_node_id
                )
            """
        ).fetchall()
    finally:
        conn.close()


def _fleet_rows():
    conn = get_db_connection()
    try:
        return conn.execute(
            """SELECT mo.observer_node_id, observer.hostname AS observer_hostname,
                      mo.peer_node_id, peer.hostname AS peer_hostname, mo.state,
                      mo.error_code, mo.last_changed_at, mo.last_reported_at
               FROM mount_observations AS mo
               JOIN fleet_nodes AS observer
                 ON observer.node_id=mo.observer_node_id
                AND observer.membership_state='active'
               JOIN fleet_nodes AS peer
                 ON peer.node_id=mo.peer_node_id
                AND peer.membership_state='active'
               ORDER BY observer.hostname, peer.hostname"""
        ).fetchall()
    finally:
        conn.close()


def _get(peer: str):
    node_id = _node_id(
        peer
    )

    conn = get_db_connection()

    try:
        return conn.execute(
            """
            SELECT
                ms.peer_node_id,
                fn.hostname,
                COALESCE(
                    mp.desired_state,
                    'mounted'
                ) AS desired_state,
                ms.state,
                ms.mount_path,
                ms.failure_count,
                ms.last_success_at,
                ms.next_retry_at,
                ms.problem_since,
                ms.error_code,
                ms.error_message
            FROM mount_state AS ms
            LEFT JOIN mount_preferences AS mp
              ON mp.peer_node_id = ms.peer_node_id
            LEFT JOIN fleet_nodes AS fn
              ON fn.node_id = ms.peer_node_id
            WHERE ms.peer_node_id = ?
            """,
            (node_id,),
        ).fetchone()
    finally:
        conn.close()


def cmd_mounts(args) -> int:
    action = args.action

    if action == "list":
        if os.geteuid() == 0:
            rows = _rows()
        else:
            from lattice.operator_client import request
            rows = request("mounts.list")

        if not rows:
            print(
                "No peer mount state has been recorded yet."
            )
            return 0

        print(
            f"{'Computer':<22} "
            f"{'Desired':<10} "
            f"{'State':<16} "
            f"{'Failures':<8} "
            f"Node ID"
        )

        for row in rows:
            label = (
                row["hostname"]
                or "peer"
            )

            print(
                f"{label:<22} "
                f"{row['desired_state']:<10} "
                f"{row['state']:<16} "
                f"{row['failure_count']:<8} "
                f"{row['peer_node_id']}"
            )

        return 0

    if action == "fleet":
        if os.geteuid() == 0:
            rows = _fleet_rows()
        else:
            from lattice.operator_client import request
            rows = request("mounts.fleet")
        if not rows:
            print("No fleet-wide mount observations have been reported yet.")
            return 0
        print(f"{'Observer':<22} {'Peer':<22} {'State':<16} {'Reported':<27} Error")
        for row in rows:
            observer = row["observer_hostname"] or row["observer_node_id"]
            peer = row["peer_hostname"] or row["peer_node_id"]
            print(
                f"{observer:<22} {peer:<22} {row['state']:<16} "
                f"{row['last_reported_at']:<27} {row['error_code'] or '-'}"
            )
        return 0

    if action == "get":
        if not args.peer:
            print(
                "Peer Node ID required."
            )
            return 1

        try:
            if os.geteuid() == 0:
                row = _get(args.peer)
            else:
                from lattice.operator_client import request
                row = request("mounts.get", {"peer": args.peer})
        except MountManagerError as exc:
            print(
                f"ERROR: {exc}"
            )
            return 1

        if row is None:
            print(
                "No mount state exists for that peer."
            )
            return 1

        print(
            f"Node ID: {row['peer_node_id']}\n"
            f"Computer: {row['hostname'] or 'unknown'}\n"
            f"Desired: {row['desired_state']}\n"
            f"State: {row['state']}\n"
            f"Mount path: {row['mount_path'] or 'not mounted'}\n"
            f"Failures: {row['failure_count']}\n"
            f"Last success: {row['last_success_at'] or 'never'}\n"
            f"Next retry: {row['next_retry_at'] or 'none'}\n"
            f"Problem since: {row['problem_since'] or 'none'}\n"
            f"Error code: {row['error_code'] or 'none'}\n"
            f"Error: {row['error_message'] or 'none'}"
        )

        return 0

    if action in {
        "pause",
        "unmount",
        "resume",
        "mount",
    }:
        if not args.peer:
            print(
                "Peer Node ID required."
            )
            return 1

        try:
            node_id = _node_id(
                args.peer
            )

            desired = (
                "paused"
                if action
                in {
                    "pause",
                    "unmount",
                }
                else "mounted"
            )

            set_mount_preference(
                node_id,
                desired,
            )

        except MountManagerError as exc:
            print(
                f"ERROR: {exc}"
            )
            return 1

        _wake_manager()

        if desired == "paused":
            print(
                f"{node_id} is persistently paused. "
                "Lattice will not remount it until you mount/resume it."
            )
        else:
            print(
                f"{node_id} is set to mounted. "
                "Immediate reconciliation requested."
            )

        return 0

    print(
        f"Unknown mount action: {action}"
    )
    return 1
