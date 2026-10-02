"""Persistent connection metadata for the trusted shell channel.

No command text, stdout, stderr, environment, or session contents are stored.
Only connection state, peer identity, route, and timestamps are recorded.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json

from lattice.core.config import load_config
from lattice.core.db import get_db_connection
from lattice.core.lan_routes import is_local_only_virtual_interface


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _worker_id(conn, node_id: str) -> int | None:
    row = conn.execute(
        "SELECT worker_id FROM fleet_nodes WHERE node_id=?",
        (node_id,),
    ).fetchone()
    if row is None or row["worker_id"] is None:
        return None
    return int(row["worker_id"])


def _history(conn, node_id: str, hostname: str, event_type: str, ip: str | None, details: dict | None = None) -> None:
    conn.execute(
        """INSERT INTO shell_connection_history
           (peer_node_id, hostname, event_type, ip, occurred_at, details)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (node_id, hostname, event_type, ip, _now(), json.dumps(details, sort_keys=True) if details else None),
    )

def mark_connected(node_id: str, hostname: str, ip: str) -> None:
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM shell_connection_state WHERE peer_node_id=?",
            (node_id,),
        ).fetchone()
        previous_state = row["state"] if row is not None else "unknown"
        previous_ip = row["selected_ip"] if row is not None else None
        alert_id = row["alert_id"] if row is not None else None
        event_type = None
        if previous_state == "unavailable":
            event_type = "recovered"
        elif previous_state != "connected":
            event_type = "connected"
        elif previous_ip and previous_ip != ip:
            event_type = "route_switch"
        now = _now()
        conn.execute(
            """INSERT INTO shell_connection_state
               (peer_node_id, hostname, state, selected_ip, failure_count,
                problem_since, last_attempt_at, last_connected_at, alert_id, updated_at)
               VALUES (?, ?, 'connected', ?, 0, NULL, ?, ?, NULL, ?)
               ON CONFLICT(peer_node_id) DO UPDATE SET
                 hostname=excluded.hostname, state='connected', selected_ip=excluded.selected_ip,
                 failure_count=0, problem_since=NULL, last_attempt_at=excluded.last_attempt_at,
                 last_connected_at=excluded.last_connected_at, alert_id=NULL,
                 updated_at=excluded.updated_at""",
            (node_id, hostname, ip, now, now, now),
        )
        if event_type:
            _history(conn, node_id, hostname, event_type, ip)
        if alert_id is not None:
            event = conn.execute(
                """INSERT INTO events (timestamp, worker_id, type, severity, message, details)
                   VALUES (?, ?, 'shell_access.connection_recovered', 'ok', ?, ?)""",
                (now, _worker_id(conn, node_id), f"Trusted shell connection to {hostname} recovered.",
                 json.dumps({"peer_node_id": node_id, "ip": ip}, sort_keys=True)),
            )
            conn.execute(
                "UPDATE alerts SET resolved_at=?, resolution_event_id=? WHERE id=? AND resolved_at IS NULL",
                (now, event.lastrowid, alert_id),
            )
        conn.execute(
            """INSERT INTO peer_routes (node_id, ip, source, last_seen_at, last_success_at, failure_count)
               VALUES (?, ?, 'dns', ?, ?, 0)
               ON CONFLICT(node_id, ip) DO UPDATE SET
                 last_seen_at=excluded.last_seen_at, last_success_at=excluded.last_success_at,
                 failure_count=0""",
            (node_id, ip, now, now),
        )
        conn.commit()
    finally:
        conn.close()

def mark_unavailable(node_id: str, hostname: str, attempted_ips: list[str], error: str) -> None:
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM shell_connection_state WHERE peer_node_id=?",
            (node_id,),
        ).fetchone()
        now = _now()
        first_failure = row["problem_since"] if row is not None and row["problem_since"] else now
        failure_count = int(row["failure_count"] or 0) + 1 if row is not None else 1
        alert_id = row["alert_id"] if row is not None else None
        previous_state = row["state"] if row is not None else "unknown"
        conn.execute(
            """INSERT INTO shell_connection_state
               (peer_node_id, hostname, state, failure_count, problem_since,
                last_attempt_at, last_disconnected_at, alert_id, updated_at)
               VALUES (?, ?, 'unavailable', ?, ?, ?, ?, ?, ?)
               ON CONFLICT(peer_node_id) DO UPDATE SET
                 hostname=excluded.hostname, state='unavailable',
                 failure_count=excluded.failure_count,
                 problem_since=COALESCE(shell_connection_state.problem_since, excluded.problem_since),
                 last_attempt_at=excluded.last_attempt_at,
                 last_disconnected_at=excluded.last_disconnected_at,
                 updated_at=excluded.updated_at""",
            (node_id, hostname, failure_count, first_failure, now, now, alert_id, now),
        )
        if previous_state != "unavailable":
            _history(conn, node_id, hostname, "unavailable", attempted_ips[0] if attempted_ips else None,
                     {"attempted_ips": attempted_ips, "error": error[:300]})
        for ip in attempted_ips:
            conn.execute(
                """UPDATE peer_routes SET failure_count=failure_count+1,
                   last_failure_at=? WHERE node_id=? AND ip=?""",
                (now, node_id, ip),
            )
        if alert_id is None:
            try:
                started = datetime.fromisoformat(str(first_failure))
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - started).total_seconds()
            except ValueError:
                age = float(load_config().shell_access.persistent_alert_seconds)
            if age >= load_config().shell_access.persistent_alert_seconds:
                message = f"Lattice has been unable to maintain the trusted shell connection to {hostname}."
                event = conn.execute(
                    """INSERT INTO events (timestamp, worker_id, type, severity, message, details)
                       VALUES (?, ?, 'shell_access.connection_persistent', 'error', ?, ?)""",
                    (now, _worker_id(conn, node_id), message,
                     json.dumps({"peer_node_id": node_id, "attempted_ips": attempted_ips,
                                 "failure_count": failure_count, "error": error[:500]}, sort_keys=True)),
                )
                alert = conn.execute(
                    """INSERT INTO alerts (worker_id, severity, title, message, trigger_event_id, fired_at)
                       VALUES (?, 'error', ?, ?, ?, ?)""",
                    (_worker_id(conn, node_id), f"Shell connection unavailable: {hostname}",
                     message, event.lastrowid, now),
                )
                conn.execute(
                    "UPDATE shell_connection_state SET alert_id=? WHERE peer_node_id=?",
                    (alert.lastrowid, node_id),
                )
        conn.commit()
    finally:
        conn.close()

def mark_retired(node_id: str, hostname: str) -> None:
    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT state, alert_id FROM shell_connection_state WHERE peer_node_id=?",
            (node_id,),
        ).fetchone()
        now = _now()
        if row is None or row["state"] != "retired":
            _history(conn, node_id, hostname, "retired", None)
        if row is not None and row["alert_id"] is not None:
            event = conn.execute(
                """INSERT INTO events (timestamp, worker_id, type, severity, message, details)
                   VALUES (?, ?, 'shell_access.connection_retired', 'info', ?, ?)""",
                (now, _worker_id(conn, node_id), f"Trusted shell access to {hostname} was retired.",
                 json.dumps({"peer_node_id": node_id}, sort_keys=True)),
            )
            conn.execute(
                "UPDATE alerts SET resolved_at=?, resolution_event_id=? WHERE id=? AND resolved_at IS NULL",
                (now, event.lastrowid, row["alert_id"]),
            )
        conn.execute(
            """INSERT INTO shell_connection_state
               (peer_node_id, hostname, state, updated_at)
               VALUES (?, ?, 'retired', ?)
               ON CONFLICT(peer_node_id) DO UPDATE SET
                 hostname=excluded.hostname, state='retired', alert_id=NULL,
                 problem_since=NULL, updated_at=excluded.updated_at""",
            (node_id, hostname, now),
        )
        conn.commit()
    finally:
        conn.close()


def remembered_routes(node_id: str) -> list[str]:
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT ip, interface_name, route_kind FROM peer_routes
               WHERE node_id=?
                 AND last_seen_at >= datetime('now', '-30 days')
               ORDER BY CASE WHEN last_success_at IS NULL THEN 1 ELSE 0 END,
                        last_success_at DESC, priority ASC, last_seen_at DESC
               LIMIT 16""",
            (node_id,),
        ).fetchall()
        return [
            str(row["ip"])
            for row in rows
            if (
                str(row["route_kind"] or "unknown") != "unknown"
                and not is_local_only_virtual_interface(row["interface_name"])
            )
        ]
    finally:
        conn.close()


def recent_history(limit: int = 200) -> list[dict]:
    limit = max(1, min(int(limit), 1000))
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT peer_node_id, hostname, event_type, ip, occurred_at, details
               FROM shell_connection_history ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def selected_ip(node_id: str) -> str | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT selected_ip FROM shell_connection_state WHERE peer_node_id=?",
            (node_id,),
        ).fetchone()
        return str(row["selected_ip"]) if row is not None and row["selected_ip"] else None
    finally:
        conn.close()
