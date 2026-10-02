import json
import sqlite3
import uuid
from types import SimpleNamespace

import pytest

from lattice.core.lan_routes import LanRouteError, normalize_reported_routes
from lattice.core.migrations import run_migrations
from lattice.file_access.observations import (
    MountObservationError,
    normalize_mount_observations,
    store_mount_observations,
)
from lattice.shell_access import state as shell_state


def _db(tmp_path, monkeypatch):
    path = tmp_path / "lattice.db"
    monkeypatch.setenv("LATTICE_DB_PATH", str(path))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    run_migrations(conn)
    return conn, path


def test_reported_routes_prefer_ethernet_and_refuse_public_ip():
    routes = normalize_reported_routes([
        {"ip": "10.77.0.80", "interface": "wlan0", "kind": "wifi", "priority": 20},
        {"ip": "10.77.0.40", "interface": "enp3s0", "kind": "ethernet", "priority": 10},
        {"ip": "172.17.0.1", "interface": "docker0", "kind": "unknown", "priority": 30},
        {"ip": "172.18.0.2", "interface": "veth1234", "kind": "unknown", "priority": 30},
        {"ip": "10.2.0.2", "interface": "proton-canada", "kind": "unknown", "priority": 30},
    ], allow_unknown=False)
    assert [route["ip"] for route in routes] == ["10.77.0.40", "10.77.0.80"]
    with pytest.raises(LanRouteError, match="private IPv4"):
        normalize_reported_routes([{"ip": "8.8.8.8"}])

def test_mount_observations_store_only_active_signed_peers(tmp_path, monkeypatch):
    conn, _path = _db(tmp_path, monkeypatch)
    observer = str(uuid.uuid4())
    peer = str(uuid.uuid4())
    retired = str(uuid.uuid4())
    for node_id, state in ((observer, "active"), (peer, "active"), (retired, "revoked")):
        conn.execute(
            """INSERT INTO fleet_nodes
               (node_id, hostname, role, main_user, main_uid, main_gid,
                file_key_generation, membership_state)
               VALUES (?, ?, 'worker', 'masteruser', 1000, 1000, 1, ?)""",
            (node_id, f"node-{node_id[:8]}", state),
        )
    conn.commit()
    payload = [
        {"observer_node_id": observer, "peer_node_id": peer, "state": "mounted", "error_code": None},
        {"observer_node_id": observer, "peer_node_id": retired, "state": "offline", "error_code": "gone"},
    ]
    assert store_mount_observations(conn, observer, payload) == 1
    row = conn.execute("SELECT state FROM mount_observations").fetchone()
    assert row["state"] == "mounted"
    conn.close()

    with pytest.raises(MountObservationError, match="wrong observer"):
        normalize_mount_observations(
            [{"observer_node_id": peer, "peer_node_id": observer, "state": "mounted"}],
            observer,
        )

def test_shell_connection_history_alert_and_recovery_store_no_commands(tmp_path, monkeypatch):
    conn, path = _db(tmp_path, monkeypatch)
    peer = str(uuid.uuid4())
    conn.execute("INSERT INTO workers (id, hostname) VALUES (1, 'worker-node')")
    conn.execute(
        """INSERT INTO fleet_nodes
           (node_id, worker_id, hostname, role, main_user, main_uid, main_gid,
            file_key_generation, membership_state)
           VALUES (?, 1, 'worker-node', 'worker', 'masteruser', 1000, 1000, 1, 'active')""",
        (peer,),
    )
    conn.commit(); conn.close()

    monkeypatch.setattr(
        shell_state,
        "load_config",
        lambda: SimpleNamespace(shell_access=SimpleNamespace(persistent_alert_seconds=30)),
    )
    shell_state.mark_unavailable(peer, "worker-node", ["10.77.0.20"], "connection refused")
    conn = sqlite3.connect(path)
    conn.execute(
        "UPDATE shell_connection_state SET problem_since=datetime('now','-2 minutes') WHERE peer_node_id=?",
        (peer,),
    )
    conn.commit(); conn.close()
    shell_state.mark_unavailable(peer, "worker-node", ["10.77.0.20"], "connection refused")

    conn = sqlite3.connect(path); conn.row_factory = sqlite3.Row
    state = conn.execute("SELECT alert_id FROM shell_connection_state WHERE peer_node_id=?", (peer,)).fetchone()
    assert state["alert_id"] is not None
    conn.close()
    shell_state.mark_connected(peer, "worker-node", "10.77.0.20")
    history = shell_state.recent_history()
    serialized = json.dumps(history)
    assert "unavailable" in serialized and "recovered" in serialized
    assert "sudo " not in serialized and "command" not in serialized
    conn = sqlite3.connect(path)
    assert conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"
    ).fetchone()[0] == 0
    conn.close()


def test_remembered_routes_exclude_virtual_and_expired_history(tmp_path, monkeypatch):
    conn, _path = _db(tmp_path, monkeypatch)
    peer = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO peer_routes(
               node_id,ip,interface_name,route_kind,last_seen_at,last_success_at
           ) VALUES(?,?,?,'wifi',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)""",
        (peer, "10.77.0.202", "wlan0"),
    )
    conn.execute(
        """INSERT INTO peer_routes(
               node_id,ip,interface_name,route_kind,last_seen_at,last_success_at
           ) VALUES(?,?,?,'unknown',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)""",
        (peer, "172.17.0.1", "docker0"),
    )
    conn.execute(
        """INSERT INTO peer_routes(
               node_id,ip,interface_name,route_kind,last_seen_at,last_success_at
           ) VALUES(?,?,?,'unknown',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)""",
        (peer, "10.2.0.2", "proton-canada"),
    )
    conn.execute(
        """INSERT INTO peer_routes(
               node_id,ip,interface_name,route_kind,last_seen_at,last_success_at
           ) VALUES(?,?,?,'wifi',?,?)""",
        (peer, "10.77.0.95", "wlan0", "2020-01-01 00:00:00", "2020-01-01 00:00:00"),
    )
    conn.commit()
    conn.close()

    assert shell_state.remembered_routes(peer) == ["10.77.0.202"]


def test_local_lan_routes_refreshes_cache(monkeypatch):
    import lattice.core.lan_routes as routes
    routes._ROUTE_CACHE = None
    monkeypatch.setattr(routes.shutil, "which", lambda _name: "/usr/bin/ip")

    class Result:
        returncode = 0
        stdout = (
            '[{"ifname":"wlan0","addr_info":[{"family":"inet","local":"10.77.0.200"}]},'
            '{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1"}]},'
            '{"ifname":"veth1234","addr_info":[{"family":"inet","local":"172.18.0.2"}]},'
            '{"ifname":"proton-canada","addr_info":[{"family":"inet","local":"10.2.0.2"}]}]'
        )

    monkeypatch.setattr(routes.subprocess, "run", lambda *args, **kwargs: Result())
    result = routes.local_lan_routes(cache_seconds=0)
    assert result == [{
        "ip": "10.77.0.200",
        "interface": "wlan0",
        "kind": "wifi",
        "priority": 20,
    }]


def test_local_lan_routes_uses_stale_cache_on_refresh_timeout(monkeypatch):
    import subprocess
    import time
    import lattice.core.lan_routes as routes
    routes._ROUTE_CACHE = (
        time.monotonic() - 60,
        [{
            "ip": "10.77.0.200",
            "interface": "wlan0",
            "kind": "wifi",
            "priority": 20,
        }],
    )
    monkeypatch.setattr(routes.shutil, "which", lambda _name: "/usr/bin/ip")

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd=["ip"], timeout=0.5)

    monkeypatch.setattr(routes.subprocess, "run", timeout)
    result = routes.local_lan_routes(cache_seconds=0)
    assert result == [{
        "ip": "10.77.0.200",
        "interface": "wlan0",
        "kind": "wifi",
        "priority": 20,
    }]
