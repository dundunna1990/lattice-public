"""Operator visibility for Lattice's trusted shell channel."""
from __future__ import annotations

import os

from lattice.core.db import get_db_connection
from lattice.shell_access.state import recent_history


def _status_rows():
    conn = get_db_connection()
    try:
        return conn.execute(
            """SELECT peer_node_id, hostname, state, selected_ip, failure_count,
                      problem_since, last_connected_at, last_disconnected_at
               FROM shell_connection_state
               ORDER BY hostname, peer_node_id"""
        ).fetchall()
    finally:
        conn.close()


def cmd_shell(args) -> int:
    if args.action == "status":
        if os.geteuid() == 0:
            rows = _status_rows()
        else:
            from lattice.operator_client import request
            rows = request("shell.status")
        if not rows:
            print("No trusted shell connection state has been recorded yet.")
            return 0
        print(f"{'Computer':<22} {'State':<12} {'Route':<16} {'Failures':<8} Node ID")
        for row in rows:
            print(
                f"{row['hostname']:<22} {row['state']:<12} "
                f"{(row['selected_ip'] or '-'):<16} {row['failure_count']:<8} "
                f"{row['peer_node_id']}"
            )
        return 0

    if args.action == "history":
        if os.geteuid() == 0:
            rows = recent_history(args.limit)
        else:
            from lattice.operator_client import request
            rows = request("shell.history", {"limit": args.limit})
        if not rows:
            print("No trusted shell connection history has been recorded yet.")
            return 0
        print(f"{'When':<27} {'Computer':<22} {'Event':<14} {'Route':<16} Node ID")
        for row in rows:
            print(
                f"{row['occurred_at']:<27} {row['hostname']:<22} "
                f"{row['event_type']:<14} {(row['ip'] or '-'):<16} "
                f"{row['peer_node_id']}"
            )
        return 0

    print(f"Unknown shell action: {args.action}")
    return 1
