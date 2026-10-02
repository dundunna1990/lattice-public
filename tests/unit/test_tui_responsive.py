import curses
from datetime import datetime, timedelta, timezone
import sqlite3
from types import SimpleNamespace

from lattice.cli import tui


class FakeScreen:
    def __init__(self, sizes, keys):
        self.sizes = iter(sizes)
        self.current_size = next(self.sizes)
        self.keys = iter(keys)
        self.writes = []
        self.refreshes = 0
        self.timeouts = []

    def getmaxyx(self):
        return self.current_size

    def clear(self):
        self.writes.clear()

    def erase(self):
        self.writes.clear()

    def bkgd(self, *_args):
        return None

    def addstr(self, y, x, text, *args):
        self.writes.append((y, x, text, args))

    def refresh(self):
        self.refreshes += 1

    def timeout(self, value):
        self.timeouts.append(value)

    def getch(self):
        key = next(self.keys)
        if key == curses.KEY_RESIZE:
            try:
                self.current_size = next(self.sizes)
            except StopIteration:
                pass
        return key


def _status(worker_count=0):
    workers = [
        {
            "hostname": f"worker-{index}",
            "status": "healthy",
            "last_seen": "now",
            "services_ok": 2,
            "services_fail": 0,
            "is_self": False,
        }
        for index in range(worker_count)
    ]
    return tui.LatticeStatus(
        role="master",
        master_hostname="master-node",
        master_ip="10.77.0.200",
        daemon_status="running",
        uptime="1h 2m",
        version="0.1.0",
        workers=workers,
        alerts=[],
    )


def _disable_curses(monkeypatch):
    monkeypatch.setattr(curses, "curs_set", lambda *_args: None)
    monkeypatch.setattr(curses, "start_color", lambda: None)
    monkeypatch.setattr(curses, "init_pair", lambda *_args: None)
    monkeypatch.setattr(curses, "color_pair", lambda _n: 0)


def test_control_menu_scrolls_long_lists_and_page_down(monkeypatch):
    _disable_curses(monkeypatch)
    options = [f"item-{index:02d}" for index in range(1, 61)]
    keys = [curses.KEY_NPAGE, curses.KEY_NPAGE, curses.KEY_DOWN, ord("\n")]
    screen = FakeScreen([(24, 80)], keys)

    selected = tui._control_menu(
        screen,
        "LONG MENU",
        options,
        intro=["Choose an item."],
    )

    assert selected is not None
    assert selected > 20
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)
    assert "↑ more above" in visible
    assert f"item-{selected + 1:02d}" in visible



def test_80x24_uses_compact_dashboard(monkeypatch):
    _disable_curses(monkeypatch)
    screen = FakeScreen([(24, 80)], [ord("q")])
    result = tui.show_re_run_menu(screen, _status())
    visible = " ".join(text for _y, _x, text, _args in screen.writes)
    assert result == 7
    assert "LATTICE" in visible
    assert "CURRENT MESH" in visible
    assert "MASTER DETAILS" in visible
    assert "NODE CONNECTIONS" in visible
    assert "ALERTS" in visible
    assert "DISCOVERY" in visible
    assert "Terminal too small" not in visible


def test_tiny_terminal_waits_for_resize_instead_of_exiting(monkeypatch):
    _disable_curses(monkeypatch)
    screen = FakeScreen([(12, 50), (24, 80)], [curses.KEY_RESIZE, ord("q")])
    result = tui.show_re_run_menu(screen, _status())
    assert result == 7
    assert screen.refreshes >= 2


def test_many_workers_page_without_forcing_larger_terminal(monkeypatch):
    _disable_curses(monkeypatch)
    screen = FakeScreen([(24, 80)], [curses.KEY_NPAGE, ord("q")])
    result = tui.show_re_run_menu(screen, _status(worker_count=20))
    visible = " ".join(text for _y, _x, text, _args in screen.writes)
    assert result == 7
    assert "PgUp/PgDn" in visible


class FakeDiscovery:
    def __init__(self, snapshot):
        self.value = snapshot

    def snapshot(self, _now=None):
        return dict(self.value)


def _hybrid_status():
    status = _status(worker_count=0)
    status.health = {
        "fleet": {"state": "healthy", "problems": 0, "online": 0, "nodes": 1},
        "network": {"state": "healthy", "label": "Stable (10.77.0.200)"},
        "file": {"state": "idle", "label": "No peers yet"},
        "shell": {"state": "idle", "label": "No peers yet"},
    }
    status.events = [{
        "timestamp": "2026-08-28T20:00:00+00:00",
        "severity": "ok",
        "message": "Fleet health check passed",
        "worker": "Master",
    }]
    return status


def test_hybrid_dashboard_shows_live_discovery_age_and_waiting_worker(monkeypatch):
    _disable_curses(monkeypatch)
    monkeypatch.setattr(tui.time, "monotonic", lambda: 103.0)
    discovery = FakeDiscovery({
        "scanning": False,
        "last_scan_age": 3,
        "waiting": [{
            "addr": "10.77.0.201",
            "host": "worker-node.local",
            "txt": {"hostname": "worker-node", "state": "waiting"},
        }],
        "error": None,
    })
    screen = FakeScreen([(24, 80)], [ord("q")])
    result = tui.show_re_run_menu(screen, _hybrid_status(), discovery)
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)
    assert result == 7
    assert "CURRENT MESH" in visible
    assert "MASTER DETAILS" in visible
    assert "NODE CONNECTIONS" in visible
    assert "ALERTS" in visible
    assert "DISCOVERY" in visible
    assert "● ACTIVE" in visible
    assert "Waiting 1" in visible


def test_compact_dashboard_matches_full_dashboard_semantics(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.workers[0].update({"hostname": "worker-node", "ip": "10.77.0.201"})
    status.workers[1].update({"hostname": "backup-node", "ip": "10.77.0.202"})
    status.alerts = [{
        "worker": "worker-node",
        "title": "Protected system problem: SSH",
        "severity": "warn",
    }]
    status.health = {
        "fleet": {"state": "degraded", "problems": 1, "online": 2, "nodes": 3},
        "network": {"state": "healthy", "label": "Stable (10.77.0.200)"},
        "discovery_network": "10.77.0.0/24",
        "automation": {
            "mode": "automatic", "dry_run": False,
            "breaker_label": "CLOSED", "breaker_state": "healthy",
            "last_fix": "2099-01-01T00:00:00+00:00",
        },
        "node_access": [
            {"hostname": "master-node", "file": "READY", "file_ok": True,
             "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "worker-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "backup-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
        ],
        "backup_nodes": [
            {"hostname": "master-node", "state": "healthy", "label": "HEALTHY", "ok": True},
            {"hostname": "worker-node", "state": "running", "label": "RUNNING", "ok": True},
            {"hostname": "backup-node", "state": "not_set_up", "label": "NOT SET UP", "ok": False},
        ],
    }
    status.events = [
        {"timestamp": "2099-01-01T00:00:00+00:00", "severity": "ok",
         "message": f"compact event {index}", "worker": "backup-node"}
        for index in range(1, 6)
    ]
    discovery = FakeDiscovery({
        "scanning": False, "last_scan_age": 5, "waiting": [], "error": None,
    })
    screen = FakeScreen([(24, 80)], [ord("q")])

    assert tui.show_re_run_menu(screen, status, discovery) == 7
    all_writes = "\n".join(text for _y, _x, text, _args in screen.writes)

    assert " DISCOVERY " in all_writes
    discovery_y = min(y for y, _x, text, _args in screen.writes if "DISCOVERY" in text and "┌" in text)
    alerts_y = min(y for y, _x, text, _args in screen.writes if "ALERTS" in text and "─" in text)
    mesh_y = min(y for y, _x, text, _args in screen.writes if "CURRENT MESH" in text)
    assert discovery_y < alerts_y < mesh_y
    assert "worker-node" in all_writes and "DEGRADED" in all_writes
    assert "backup-node" in all_writes and "HEALTHY" in all_writes
    assert "HB LOCAL" in all_writes and "HB just now" in all_writes
    assert "MASTER DETAILS" in all_writes
    assert "Health ● HEALTHY" in all_writes
    assert "AUTOMATION" not in all_writes
    assert "K/J Scroll" not in all_writes
    assert "NODE CONNECTIONS" in all_writes
    assert "FILE/MOUNT" in all_writes and "SHELL" in all_writes and "ADMIN" in all_writes
    assert "BACKUP" in all_writes
    assert "RUNNING" in all_writes
    assert "NOT SET UP" in all_writes
    assert "RECENT LOGS" in all_writes
    assert "compact event 1" in all_writes
    assert "compact event 2" not in all_writes
    assert "compact event 3" not in all_writes


def test_tall_compact_dashboard_keeps_controls_directly_below_logs(monkeypatch):
    _disable_curses(monkeypatch)
    status = _hybrid_status()
    status.health["discovery_network"] = "10.77.0.0/24"
    status.health["node_access"] = [{
        "hostname": "master-node", "file": "READY", "file_ok": True,
        "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True,
    }]
    screen = FakeScreen([(50, 67)], [ord("q")])

    assert tui._dashboard_mode(50, 67) == "compact"
    assert tui.show_re_run_menu(screen, status) == 7
    log_y = max(
        y for y, _x, text, _args in screen.writes
        if "Fleet health check passed" in text
    )
    action_y = min(
        y for y, _x, text, _args in screen.writes
        if "[1]Add" in text
    )
    separator_y = min(
        y for y, _x, text, _args in screen.writes
        if text.startswith("─") and y > log_y
    )
    assert separator_y == log_y + 1
    assert action_y == separator_y + 1



def test_compact_master_details_colors_each_status_value(monkeypatch):
    monkeypatch.setattr(curses, "curs_set", lambda *_args: None)
    monkeypatch.setattr(curses, "start_color", lambda: None)
    monkeypatch.setattr(curses, "init_pair", lambda *_args: None)
    monkeypatch.setattr(curses, "color_pair", lambda number: number)

    status = _hybrid_status()
    status.health["discovery_network"] = "10.77.0.0/24"
    status.health["node_access"] = [{
        "hostname": "master-node", "file": "READY", "file_ok": True,
        "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True,
    }]
    screen = FakeScreen([(30, 80)], [ord("q")])

    assert tui.show_re_run_menu(screen, status) == 7
    colored_spans = {
        text: args[0] for _y, _x, text, args in screen.writes
        if text in {"● HEALTHY", "● STABLE", "● RUNNING"} and args
    }
    assert colored_spans["● HEALTHY"] == 4
    assert colored_spans["● STABLE"] == 4
    assert colored_spans["● RUNNING"] == 4

def test_discovery_monitor_scan_once_records_real_result(monkeypatch):
    times = iter([50.0, 53.0])
    monkeypatch.setattr(tui.time, "monotonic", lambda: next(times))
    monitor = tui.DiscoveryMonitor(
        discover_fn=lambda timeout: [{"addr": "10.77.0.201", "txt": {"hostname": "worker"}}]
    )
    monitor.scan_once()
    snap = monitor.snapshot()
    assert snap["scanning"] is False
    assert snap["error"] is None
    assert snap["last_scan_age"] == 3
    assert snap["waiting"][0]["addr"] == "10.77.0.201"


def test_discovery_monitor_surfaces_scan_error(monkeypatch):
    monkeypatch.setattr(tui.time, "monotonic", lambda: 10.0)
    def fail(timeout):
        raise RuntimeError("avahi unavailable")
    monitor = tui.DiscoveryMonitor(discover_fn=fail)
    monitor.scan_once()
    snap = monitor.snapshot(now=12.0)
    assert snap["scanning"] is False
    assert snap["waiting"] == []
    assert snap["error"] == "avahi unavailable"
    assert snap["last_scan_age"] == 2


def test_transport_health_does_not_claim_success_without_transport_state():
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE mount_state (state TEXT)")
    conn.execute("CREATE TABLE shell_connection_state (state TEXT)")
    file_health, shell_health = tui._transport_health(conn, 2)
    assert file_health["state"] == "unknown"
    assert shell_health["state"] == "unknown"
    assert file_health["label"] == "0/2 known"
    assert shell_health["label"] == "0/2 known"


def test_transport_health_reports_real_connected_and_mounted_counts():
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE mount_state (state TEXT)")
    conn.execute("CREATE TABLE shell_connection_state (state TEXT)")
    conn.executemany("INSERT INTO mount_state(state) VALUES (?)", [("mounted",), ("mounted",)])
    conn.executemany("INSERT INTO shell_connection_state(state) VALUES (?)", [("connected",), ("connected",)])
    file_health, shell_health = tui._transport_health(conn, 2)
    assert file_health["state"] == "healthy"
    assert shell_health["state"] == "healthy"
    assert file_health["ok"] == 2
    assert shell_health["ok"] == 2


def test_fleet_health_degrades_for_real_worker_problem():
    fleet = tui._fleet_health(
        "running",
        [{"status": "down"}],
        [],
        {"state": "healthy"},
        {"state": "healthy"},
        {"state": "healthy"},
    )
    assert fleet["state"] == "degraded"
    assert fleet["problems"] == 1


def test_add_worker_action_stays_inside_tui_and_returns_to_dashboard(monkeypatch):
    _disable_curses(monkeypatch)
    discovery = FakeDiscovery({
        "scanning": False,
        "last_scan_age": 1,
        "waiting": [{
            "addr": "10.77.0.103",
            "host": "worker-node.local",
            "txt": {
                "hostname": "worker-node",
                "state": "waiting",
                "pairing_id": "pair-123",
            },
        }],
        "error": None,
    })
    # Dashboard Enter -> choose worker Enter -> type code -> Enter -> success acknowledgement -> Q dashboard.
    keys = [ord("\n"), ord("\n")] + [ord(c) for c in "ABC123"] + [ord("\n"), ord("x"), ord("q")]
    screen = FakeScreen([(24, 80)], keys)

    import lattice.pairing
    calls = []
    monkeypatch.setattr(
        lattice.pairing,
        "pair_worker",
        lambda **kwargs: (calls.append(kwargs) or {"hostname": "worker-node", "ip": "10.77.0.201"}),
    )

    result = tui.show_re_run_menu(screen, _hybrid_status(), discovery)

    assert result == 7
    assert len(calls) == 1
    assert calls[0]["hostname"] == "worker-node"
    assert calls[0]["worker_ip"] == "10.77.0.103"
    assert calls[0]["pairing_id"] == "pair-123"
    assert calls[0]["code"] == "ABC123"


def test_fleet_health_degrades_for_incomplete_pairing_state():
    for state in ("configuring", "needs_attention"):
        fleet = tui._fleet_health(
            "running",
            [{"status": state}],
            [],
            {"state": "healthy"},
            {"state": "healthy"},
            {"state": "healthy"},
        )
        assert fleet["state"] == "degraded"
        assert fleet["problems"] == 1


def test_modal_getch_disables_refresh_timeout_until_real_key():
    screen = FakeScreen([(24, 80)], [ord("x")])
    assert tui._modal_getch(screen) == ord("x")
    assert screen.timeouts == [-1, 1000]


def test_node_access_uses_real_transport_and_applied_admin_state(monkeypatch):
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE fleet_state (id INTEGER PRIMARY KEY, generation INTEGER)")
    conn.execute(
        "CREATE TABLE fleet_nodes (node_id TEXT, hostname TEXT, role TEXT, "
        "file_transport_generation INTEGER, shell_transport_generation INTEGER, "
        "membership_state TEXT)"
    )
    conn.execute("CREATE TABLE mount_state (peer_node_id TEXT, state TEXT)")
    conn.execute("CREATE TABLE shell_connection_state (peer_node_id TEXT, state TEXT)")
    conn.execute("CREATE TABLE workers (id INTEGER, hostname TEXT, removed_at TEXT)")
    conn.execute(
        "CREATE TABLE services (worker_id INTEGER, name TEXT, status TEXT, last_reported_at TEXT)"
    )
    conn.execute("INSERT INTO workers VALUES (1, 'worker-node', NULL)")
    conn.execute(
        "INSERT INTO services VALUES (1, 'file_export', 'healthy', ?)",
        (datetime.now(timezone.utc).isoformat(),),
    )
    conn.execute("INSERT INTO fleet_state VALUES (1, 7)")
    conn.execute(
        "INSERT INTO fleet_nodes VALUES ('master-id','master-node','master',7,7,'active')"
    )
    conn.execute(
        "INSERT INTO fleet_nodes VALUES ('worker-id','worker-node','worker',7,7,'active')"
    )
    conn.execute("INSERT INTO mount_state VALUES ('worker-id','mounted')")
    conn.execute("INSERT INTO shell_connection_state VALUES ('worker-id','connected')")

    import lattice.file_access.identity as identity_mod
    import lattice.file_access.home_export as home_export_mod
    monkeypatch.setattr(
        identity_mod, "load_node_identity", lambda: SimpleNamespace(node_id="master-id")
    )
    monkeypatch.setattr(home_export_mod, "home_bind_is_current", lambda identity: True)

    workers = [{"hostname": "worker-node"}]
    rows = tui._node_access_status(conn, "master-node", "running", workers)

    assert rows[0]["hostname"] == "master-node"
    assert rows[0]["file"] == "READY"
    assert rows[0]["shell"] == "READY"
    assert rows[0]["admin"] == "READY"
    assert rows[1]["file"] == "CONNECTED"
    assert rows[1]["shell"] == "CONNECTED"
    assert rows[1]["admin"] == "READY"

    conn.execute(
        "UPDATE fleet_nodes SET shell_transport_generation=6 WHERE hostname='worker-node'"
    )
    rows = tui._node_access_status(conn, "master-node", "running", workers)
    assert rows[1]["shell"] == "CONNECTED"
    assert rows[1]["admin"] == "NOT READY"

    # A technically mounted SSHFS path must not remain green when the Worker
    # reports that its dedicated Home export is not the real Home bind.
    conn.execute(
        "UPDATE services SET status='unhealthy' "
        "WHERE worker_id=1 AND name='file_export'"
    )
    rows = tui._node_access_status(conn, "master-node", "running", workers)
    assert rows[1]["file"] == "DOWN"
    assert rows[1]["file_ok"] is False


def test_tall_80_column_dashboard_keeps_roomy_layout_and_bottom_controls(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.workers[0].update({"hostname": "worker-node", "ip": "10.77.0.201"})
    status.workers[1].update({"hostname": "backup-node", "ip": "10.77.0.202"})
    status.alerts = [{
        "worker": "worker-node",
        "title": "Protected system problem: SSH",
        "severity": "warn",
    }]
    status.health = {
        "fleet": {"state": "degraded", "problems": 1, "online": 2, "nodes": 3},
        "network": {"state": "healthy", "label": "Stable (10.77.0.200)"},
        "discovery_network": "10.77.0.0/24",
        "automation": {
            "mode": "automatic", "dry_run": False,
            "breaker_label": "CLOSED", "breaker_state": "healthy",
            "last_fix": "2099-01-01T00:00:00+00:00",
        },
        "node_access": [
            {"hostname": "master-node", "file": "READY", "file_ok": True,
             "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "worker-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "backup-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
        ],
    }
    discovery = FakeDiscovery({
        "scanning": False, "last_scan_age": 2, "waiting": [], "error": None,
    })
    screen = FakeScreen([(58, 80)], [ord("q")])

    result = tui.show_re_run_menu(screen, status, discovery)
    rows = {y: text.rstrip() for y, _x, text, _args in screen.writes}
    visible = "\n".join(rows[y] for y in sorted(rows))

    assert result == 7
    assert tui._dashboard_mode(58, 80) == "full"
    assert "/     \\" in visible
    assert "FLEET   ⚠ DEGRADED       NODES   ● 3/3       ALERTS   ⚠ 1" in visible
    assert " DISCOVERY " in visible
    assert "● ACTIVE   Network 10.77.0.0/24   Scan 2s ago   Waiting 0" in visible
    discovery_y = min(y for y, _x, text, _args in screen.writes if "DISCOVERY" in text)
    alerts_y = min(y for y, _x, text, _args in screen.writes if "ALERTS" in text and "─" in text)
    mesh_y = min(y for y, _x, text, _args in screen.writes if "CURRENT MESH" in text)
    assert discovery_y < alerts_y < mesh_y
    all_writes = "\n".join(text for _y, _x, text, _args in screen.writes)
    assert "Health      ● HEALTHY" in all_writes
    assert "DEGRADED" in visible  # worker-node has the active alert
    assert "Network     ● STABLE" in all_writes
    assert "⚠ worker-node" in visible
    assert "Protected system problem: SSH" in visible
    assert "NODE CONNECTIONS" in visible
    all_writes = "\n".join(text for _y, _x, text, _args in screen.writes)
    assert "HB LOCAL" in all_writes
    assert "HB just now" in all_writes
    assert "FILE / MOUNT" in all_writes and "SHELL" in all_writes and "ADMIN" in all_writes
    assert "● worker-node" in all_writes
    assert "● CONNECTED" in all_writes and "● READY" in all_writes
    assert "[1] Add Computer" in rows[53]
    assert "[2] Remove Computer" in rows[53]
    assert "[3] Backups" in rows[53]
    assert "[4] Settings" in rows[53]
    assert "[5] Health Check" in rows[54]
    assert "[6] FIX" in rows[54]
    assert "[7] Reset Lattice" in rows[54]
    assert "[8] Exit" in rows[54]
    assert "K/J Scroll" in rows[55]
    assert rows[55].endswith("Q Exit")




def test_68x44_terminal_uses_full_mesh_view(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.workers[0].update({"hostname": "worker-node", "ip": "10.77.0.201"})
    status.workers[1].update({"hostname": "backup-node", "ip": "10.77.0.202"})
    screen = FakeScreen([(44, 68)], [ord("q")])

    assert tui._dashboard_mode(44, 68) == "full"
    assert tui.show_re_run_menu(screen, status) == 7
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)
    assert "CURRENT MESH" in visible
    assert "worker-node" in visible
    assert "backup-node" in visible
    assert "[1] Add" in visible
    assert "[1]Add" not in visible


def test_dashboard_canvas_never_exceeds_70_columns_or_54_rows(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.health = {
        "fleet": {"state": "healthy", "problems": 0, "online": 2, "nodes": 3},
        "network": {"state": "healthy", "label": "Stable"},
        "discovery_network": "10.77.0.0/24",
        "node_access": [],
    }
    screen = FakeScreen([(70, 120)], [ord("q")])

    assert tui.show_re_run_menu(screen, status) == 7
    assert tui.FULL_WIDTH == 70
    assert tui.MAX_DASHBOARD_HEIGHT == 54
    assert tui._dashboard_mode(54, 70) == "full"
    assert tui._dashboard_mode(44, 68) == "full"
    assert tui._dashboard_mode(43, 68) == "compact"
    assert tui._dashboard_mode(44, 67) == "compact"
    assert tui._dashboard_mode(43, 67) == "compact"

    top = (70 - 54) // 2
    left = (120 - 70) // 2
    assert min(y for y, _x, _text, _args in screen.writes) >= top
    assert max(y for y, _x, _text, _args in screen.writes) < top + 54
    assert min(x for _y, x, _text, _args in screen.writes) >= left
    assert max(x + len(text) for _y, x, text, _args in screen.writes) <= left + 70

def test_backup_node_statuses_show_setup_enabled_and_health_states():
    now = datetime.now(timezone.utc).isoformat()

    class FakeResult:
        def fetchall(self):
            return [
                ("master-node", 1, 0, "healthy", "successful", now, 0, 0, now, 1, 1, "healthy", now),
                ("worker-node", None, None, None, None, None, None, None, None, None, None, None, None),
                ("backup-node", 0, 0, None, None, None, 0, 0, None, 1, 1, "healthy", now),
            ]

    class FakeConn:
        def execute(self, _sql, _params):
            return FakeResult()

    rows = tui._backup_node_statuses(
        FakeConn(),
        "master-node",
        [{"hostname": "worker-node"}, {"hostname": "backup-node"}],
    )
    by_host = {row["hostname"]: row for row in rows}

    assert by_host["master-node"]["label"] == "HEALTHY"
    assert by_host["master-node"]["ok"] is True
    assert by_host["worker-node"]["label"] == "NOT SET UP"
    assert by_host["worker-node"]["ok"] is False
    assert by_host["backup-node"]["label"] == "OFF"
    assert by_host["backup-node"]["ok"] is False


def test_automation_summary_uses_persisted_mode_breakers_and_real_fixes():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE circuit_breaker_state (state TEXT NOT NULL);
        CREATE TABLE events (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, type TEXT NOT NULL, details TEXT
        );
        INSERT INTO config VALUES ('autoheal.mode', 'automatic');
        INSERT INTO circuit_breaker_state VALUES ('closed');
        INSERT INTO circuit_breaker_state VALUES ('open');
        INSERT INTO events VALUES (1, '2026-09-01T01:00:00+00:00',
            'network.reconcile_recovered', '{"state":"repaired"}');
        INSERT INTO events VALUES (2, '2026-09-01T02:00:00+00:00',
            'network.reconcile_recovered', '{"state":"healthy"}');
        """
    )
    config = SimpleNamespace(daemon=SimpleNamespace(dry_run=False))

    summary = tui._automation_summary(conn, config)
    conn.close()

    assert summary["mode"] == "automatic"
    assert summary["dry_run"] is False
    assert summary["breaker_label"] == "1 OPEN"
    assert summary["breaker_state"] == "degraded"
    assert summary["last_fix"] == "2026-09-01T01:00:00+00:00"


def test_full_dashboard_scrolls_when_content_exceeds_view(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.workers[0].update({"hostname": "worker-node", "ip": "10.77.0.201"})
    status.workers[1].update({"hostname": "backup-node", "ip": "10.77.0.202"})
    status.health = {
        "fleet": {"state": "healthy", "problems": 0, "online": 2, "nodes": 3},
        "network": {"state": "healthy", "label": "Stable"},
        "discovery_network": "10.77.0.0/24",
        "automation": {
            "mode": "automatic", "dry_run": False,
            "breaker_label": "CLOSED", "breaker_state": "healthy", "last_fix": None,
        },
        "node_access": [
            {"hostname": "master-node", "file": "READY", "file_ok": True,
             "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "worker-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "backup-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
        ],
    }
    status.events = [
        {"timestamp": "2099-01-01T00:00:00+00:00", "severity": "ok",
         "message": f"event {i}", "worker": "backup-node"}
        for i in range(5)
    ]
    status.problems = [
        {"timestamp": "2099-01-01T00:00:00+00:00", "severity": "error",
         "message": f"problem {i}", "worker": "worker-node", "outcome": "RECOVERED"}
        for i in range(5)
    ]

    top = FakeScreen([(44, 68)], [ord("q")])
    assert tui.show_re_run_menu(top, status) == 7
    top_text = "\n".join(text for _y, _x, text, _args in top.writes)
    assert "CURRENT MESH" in top_text
    assert "problem 4" not in top_text
    assert "K/J Scroll" in top_text

    bottom = FakeScreen([(44, 68)], [curses.KEY_END, ord("q")])
    assert tui.show_re_run_menu(bottom, status) == 7
    bottom_text = "\n".join(text for _y, _x, text, _args in bottom.writes)
    assert "RECENT PROBLEMS" in bottom_text
    assert "problem 4" in bottom_text
    assert "→ RECOVERED" in bottom_text
    assert "K/J Scroll" in bottom_text


def test_heartbeat_display_uses_existing_30_second_stale_boundary():
    now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    label, state = tui._heartbeat_display(now - timedelta(seconds=3), now=now)
    assert label == "HB 3s ago"
    assert state == "fresh"

    assert tui._heartbeat_display(now - timedelta(seconds=20), now=now)[1] == "fresh"
    assert tui._heartbeat_display(now - timedelta(seconds=21), now=now)[1] == "warning"
    assert tui._heartbeat_display(now - timedelta(seconds=29), now=now)[1] == "warning"
    assert tui._heartbeat_display(now - timedelta(seconds=30), now=now)[1] == "stale"
    assert tui._heartbeat_display("—", now=now) == ("HB UNKNOWN", "unknown")


def test_full_dashboard_layout_matches_selected_sections(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.workers[0].update({"hostname": "worker-node", "ip": "10.77.0.201"})
    status.workers[1].update({"hostname": "backup-node", "ip": "10.77.0.202"})
    status.health = {
        "fleet": {"state": "healthy", "problems": 0, "online": 2, "nodes": 3},
        "network": {"state": "healthy", "label": "Stable (10.77.0.200)"},
        "discovery_network": "10.77.0.0/24",
        "automation": {
            "mode": "automatic", "dry_run": False,
            "breaker_label": "CLOSED", "breaker_state": "healthy",
            "last_fix": "2099-01-01T00:00:00+00:00",
        },
        "node_access": [
            {"hostname": "master-node", "file": "READY", "file_ok": True,
             "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "worker-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "backup-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
        ],
        "backup_nodes": [
            {"hostname": "master-node", "state": "healthy", "label": "HEALTHY", "ok": True},
            {"hostname": "worker-node", "state": "ready", "label": "READY", "ok": True},
            {"hostname": "backup-node", "state": "degraded", "label": "DEGRADED", "ok": False},
        ],
    }
    discovery = FakeDiscovery({
        "scanning": False, "last_scan_age": 4, "waiting": [], "error": None,
    })
    screen = FakeScreen([(60, 100)], [ord("q")])

    result = tui.show_re_run_menu(screen, status, discovery)
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)
    all_writes = visible

    assert result == 7
    assert "FLEET   ● HEALTHY       NODES   ● 3/3       ALERTS   ✓ 0" in visible
    assert "DISCOVERY" in visible and "● ACTIVE" in visible
    assert "10.77.0.0/24" in visible
    assert "✓ NO ALERTS" in visible
    assert visible.index("DISCOVERY") < visible.index("✓ NO ALERTS") < visible.index("CURRENT MESH")
    assert "CURRENT MESH" in visible
    assert "● master-node" in visible
    assert "worker-node" in visible and "backup-node" in visible
    assert "MASTER DETAILS" in visible
    assert "Health      ● HEALTHY" in all_writes
    assert "AUTOMATION" in all_writes
    assert "Auto-Heal  ● AUTOMATIC" in all_writes
    assert "Dry Run    ○ OFF" in all_writes
    assert "Breakers   ✓ CLOSED" in all_writes
    assert "Last Fix   ✓" in all_writes
    assert "Workers" not in visible
    assert "NODE CONNECTIONS" in visible
    assert "FILE / MOUNT" in all_writes and "SHELL" in all_writes and "ADMIN" in all_writes
    assert "BACKUP" in all_writes
    assert "DEGRADED" in all_writes
    assert "● worker-node" in all_writes and "● CONNECTED" in all_writes


def test_recent_logs_use_persisted_events_and_sit_above_footer(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=2)
    status.workers[0].update({"hostname": "worker-node", "ip": "10.77.0.201"})
    status.workers[1].update({"hostname": "backup-node", "ip": "10.77.0.202"})
    status.health = {
        "fleet": {"state": "healthy", "problems": 0, "online": 2, "nodes": 3},
        "network": {"state": "healthy", "label": "Stable (10.77.0.200)"},
        "discovery_network": "10.77.0.0/24",
        "node_access": [
            {"hostname": "master-node", "file": "READY", "file_ok": True,
             "shell": "READY", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "worker-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
            {"hostname": "backup-node", "file": "CONNECTED", "file_ok": True,
             "shell": "CONNECTED", "shell_ok": True, "admin": "READY", "admin_ok": True},
        ],
    }
    status.events = [
        {"timestamp": "2099-01-01T00:00:00+00:00", "severity": severity,
         "message": f"event message {index}", "worker": "worker-node"}
        for index, severity in enumerate(["ok", "info", "warn", "error", "ok"], start=1)
    ]
    outcomes = ["RECOVERED", "RESTARTED", "REPAIRED", "NO CHANGE", "ATTENTION"]
    status.problems = [
        {"timestamp": "2099-01-01T00:00:00+00:00", "severity": severity,
         "message": f"problem message {index}", "worker": "backup-node",
         "outcome": outcomes[index - 1]}
        for index, severity in enumerate(["warn", "error", "critical", "warning", "error"], start=1)
    ]
    discovery = FakeDiscovery({"scanning": False, "last_scan_age": 2, "waiting": [], "error": None})
    screen = FakeScreen([(58, 80)], [curses.KEY_END, ord("q")])

    assert tui.show_re_run_menu(screen, status, discovery) == 7
    rows = {y: text.rstrip() for y, _x, text, _args in screen.writes if _x == 6}
    visible = "\n".join(rows[y] for y in sorted(rows))
    all_writes = "\n".join(text for _y, _x, text, _args in screen.writes)

    assert "RECENT LOGS" in visible
    for index in range(1, 6):
        assert f"event message {index}" in all_writes
    assert "RECENT PROBLEMS" in visible
    for index in range(1, 6):
        assert f"problem message {index}" in all_writes
    for outcome in outcomes:
        assert f"→ {outcome}" in all_writes
    assert visible.index("NODE CONNECTIONS") < visible.index("RECENT LOGS")
    assert visible.index("RECENT LOGS") < visible.index("RECENT PROBLEMS")
    assert max(y for y, _x, text, _args in screen.writes if "problem message" in text) < 54


def test_problem_history_survives_newer_routine_events():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE workers (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL);
        CREATE TABLE events (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, worker_id INTEGER,
            type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, details TEXT
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY, worker_id INTEGER, trigger_event_id INTEGER,
            resolved_at TEXT, resolution_event_id INTEGER
        );
        INSERT INTO workers(id, hostname) VALUES (1, 'worker-node');
        """
    )
    event_id = 1
    for index, severity in enumerate(["warn", "error", "critical", "warning", "error", "warn"], start=1):
        conn.execute(
            "INSERT INTO events VALUES (?, ?, 1, 'health_check', ?, ?, NULL)",
            (event_id, f"2026-09-01T00:0{index}:00+00:00", severity, f"problem {index}"),
        )
        event_id += 1
    for index in range(10):
        conn.execute(
            "INSERT INTO events VALUES (?, ?, 1, 'health_check', 'ok', ?, NULL)",
            (event_id, f"2026-09-02T00:{index:02d}:00+00:00", f"healthy {index}"),
        )
        event_id += 1

    recent = tui._dashboard_event_history(conn.cursor())
    problems = tui._dashboard_event_history(conn.cursor(), problems_only=True)
    conn.close()

    assert all(event["message"].startswith("healthy") for event in recent)
    assert [event["message"] for event in problems] == [
        "problem 6", "problem 5", "problem 4", "problem 3", "problem 2"
    ]
    assert all(event["outcome"] == "RECOVERED" for event in problems)


def test_problem_outcome_reports_recorded_repair_action():
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE workers (id INTEGER PRIMARY KEY, hostname TEXT NOT NULL);
        CREATE TABLE events (
            id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, worker_id INTEGER,
            type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, details TEXT
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY, worker_id INTEGER, trigger_event_id INTEGER,
            resolved_at TEXT, resolution_event_id INTEGER
        );
        INSERT INTO workers(id, hostname) VALUES (1, 'worker-node');
        INSERT INTO events VALUES (1, '2026-09-01T00:00:00+00:00', 1, 'health_check', 'error', 'worker failed', NULL);
        INSERT INTO events VALUES (2, '2026-09-01T00:00:10+00:00', 1, 'autoheal.success', 'info', 'Auto-heal verified recovery', NULL);
        INSERT INTO events VALUES (3, '2026-09-01T00:00:20+00:00', 1, 'health_check', 'ok', 'worker healthy', NULL);
        INSERT INTO events VALUES (4, '2026-09-01T01:00:00+00:00', 1, 'network.reconcile_failed', 'error', 'network failed', NULL);
        INSERT INTO events VALUES (5, '2026-09-01T01:00:10+00:00', 1, 'network.reconcile_recovered', 'ok', 'network repaired', '{"state":"repaired"}');
        INSERT INTO alerts VALUES (1, 1, 4, '2026-09-01T01:00:10+00:00', 5);
        INSERT INTO events VALUES (6, '2026-09-01T02:00:00+00:00', 1, 'autoheal.protected_issue', 'warn', 'SSH unavailable', NULL);
        INSERT INTO alerts VALUES (2, 1, 6, NULL, NULL);
        """
    )

    assert tui._problem_outcome(conn.cursor(), 1, 1, "health_check") == "RESTARTED"
    assert tui._problem_outcome(conn.cursor(), 4, 1, "network.reconcile_failed") == "REPAIRED"
    assert tui._problem_outcome(conn.cursor(), 6, 1, "autoheal.protected_issue") == "NO CHANGE"
    conn.close()


def test_mesh_worker_health_requires_every_operational_layer():
    now = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    worker = {
        "hostname": "worker-node",
        "status": "healthy",
        "last_seen": (now - timedelta(seconds=5)).isoformat(),
        "services_fail": 0,
    }
    access = {"file_ok": True, "shell_ok": True, "admin_ok": True}

    assert tui._mesh_worker_status(worker, access, now=now) == "HEALTHY"

    for key in ("file_ok", "shell_ok", "admin_ok"):
        broken = dict(access)
        broken[key] = False
        assert tui._mesh_worker_status(worker, broken, now=now) == "DEGRADED"

    assert tui._mesh_worker_status(
        worker, access, has_active_alert=True, now=now
    ) == "DEGRADED"
    assert tui._mesh_worker_status(
        {**worker, "services_fail": 1}, access, now=now
    ) == "DEGRADED"
    assert tui._mesh_worker_status(
        {**worker, "last_seen": (now - timedelta(seconds=30)).isoformat()},
        access, now=now
    ) == "DEGRADED"
    assert tui._mesh_worker_status(
        {**worker, "status": "down"}, access, now=now
    ) == "DOWN"
    assert tui._mesh_worker_status(
        {**worker, "status": "configuring"}, access, now=now
    ) == "CONFIGURING"


def test_mesh_master_health_requires_local_operational_layers():
    access = {"file_ok": True, "shell_ok": True, "admin_ok": True}
    assert tui._mesh_master_status("running", "healthy", access) == "HEALTHY"
    assert tui._mesh_master_status("stopped", "healthy", access) == "DEGRADED"
    assert tui._mesh_master_status("running", "degraded", access) == "DEGRADED"
    assert tui._mesh_master_status(
        "running", "healthy", access, has_active_alert=True
    ) == "DEGRADED"
    assert tui._mesh_master_status(
        "running", "healthy", {**access, "admin_ok": False}
    ) == "DEGRADED"


def test_healthy_mesh_node_symbol_pulses_without_changing_problem_symbols():
    assert tui._mesh_node_symbol("HEALTHY", True) == "●"
    assert tui._mesh_node_symbol("HEALTHY", False) == "○"
    assert tui._mesh_node_symbol("DEGRADED", True) == "●"
    assert tui._mesh_node_symbol("DEGRADED", False) == "●"
    assert tui._mesh_node_symbol("DOWN", False) == "●"
    assert tui._mesh_status_color("HEALTHY") == 4
    assert tui._mesh_status_color("DEGRADED") == 5
    assert tui._mesh_status_color("DOWN") == 6

def test_recent_log_row_colors_by_event_severity():
    base = {"timestamp": "2099-01-01T00:00:00+00:00", "worker": "node", "message": "message"}
    assert tui._recent_log_row({**base, "severity": "ok"}, 64)[1] == 4
    assert tui._recent_log_row({**base, "severity": "warn"}, 64)[1] == 5
    assert tui._recent_log_row({**base, "severity": "error"}, 64)[1] == 6


def test_recent_problem_row_keeps_problem_color_and_overlays_success_outcome():
    event = {
        "timestamp": "2099-01-01T00:00:00+00:00",
        "worker": "worker-node",
        "message": "Health check failed",
        "severity": "error",
        "outcome": "RESTARTED",
    }
    row, base_color, overlay = tui._recent_problem_row(event, 64)
    assert base_color == 6
    assert "Health check failed" in row
    assert row.endswith("→ RESTARTED")
    assert overlay is not None
    assert overlay[1:] == ("→ RESTARTED", 4)


def test_compact_70x43_keeps_five_problem_outcomes_on_existing_rows(monkeypatch):
    _disable_curses(monkeypatch)
    status = _hybrid_status()
    status.problems = [
        {
            "timestamp": "2099-01-01T00:00:00+00:00",
            "worker": "worker-node",
            "message": f"failure {index}",
            "severity": "error",
            "outcome": "RESTARTED" if index == 0 else "RECOVERED",
        }
        for index in range(5)
    ]
    screen = FakeScreen([(43, 70)], [ord("q")])

    assert tui._dashboard_mode(43, 70) == "compact"
    assert tui.show_re_run_menu(screen, status) == 7
    canvas_x = min(x for _y, x, _text, _args in screen.writes)
    base_writes = "\n".join(text for _y, x, text, _args in screen.writes if x == canvas_x)
    assert "RECENT PROBLEMS" in base_writes
    assert base_writes.count("failure ") == 5
    assert "→ RESTARTED" in base_writes
    assert base_writes.count("→ RECOVERED") == 4


def test_footer_actions_one_through_seven_stay_inside_tui(monkeypatch):
    _disable_curses(monkeypatch)
    status = _status(worker_count=0)
    called = []
    monkeypatch.setattr(tui, "_add_worker_flow", lambda *_args: called.append("add"))
    monkeypatch.setattr(tui, "_remove_worker_flow", lambda *_args: called.append("remove"))
    monkeypatch.setattr(tui, "_backups_flow", lambda *_args: called.append("backups"))
    monkeypatch.setattr(tui, "_settings_flow", lambda *_args: called.append("settings"))
    monkeypatch.setattr(tui, "_health_check_flow", lambda *_args: called.append("health"))
    monkeypatch.setattr(tui, "_fix_flow", lambda *_args: called.append("fix"))
    monkeypatch.setattr(tui, "_reset_lattice_flow", lambda *_args: called.append("reset") or False)

    expected = ["add", "remove", "backups", "settings", "health", "fix", "reset"]
    for key, name in zip("1234567", expected):
        called.clear()
        screen = FakeScreen([(58, 80)], [ord(key), ord("q")])
        assert tui.show_re_run_menu(screen, status) == 7
        assert called == [name]


def test_compact_footer_keeps_existing_height_with_clear_short_names(monkeypatch):
    _disable_curses(monkeypatch)
    screen = FakeScreen([(43, 67)], [ord("q")])
    assert tui.show_re_run_menu(screen, _status()) == 7
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)
    assert "[1]Add" in visible
    assert "[2]Rm" in visible
    assert "[3]Bkp" in visible
    assert "[4]Set" in visible
    assert "[5]Health" in visible
    assert "[6]Fix" in visible
    assert "[7]Reset" in visible
    assert "[8]Exit" in visible


def test_validated_settings_update_converts_and_rejects_bad_values():
    from lattice.core.config import LatticeConfig
    config = LatticeConfig()
    updated = tui._validated_config_update(config, "daemon.poll_interval", "15")
    assert updated.daemon.poll_interval == 15
    assert isinstance(updated.daemon.poll_interval, int)

    updated = tui._validated_config_update(config, "daemon.dry_run", "false")
    assert updated.daemon.dry_run is False

    import pytest
    with pytest.raises(Exception):
        tui._validated_config_update(config, "daemon.poll_interval", "0")


def test_remove_flow_calls_existing_secure_removal_without_terminal_prompt(monkeypatch, tmp_path):
    db = tmp_path / "remove.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE workers (hostname TEXT, ip TEXT, status TEXT, removed_at TEXT)")
    conn.execute("INSERT INTO workers VALUES ('worker-node', '10.77.0.201', 'healthy', NULL)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(tui, "get_db_connection", lambda: sqlite3.connect(db))

    choices = iter([0, 0])
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr(tui, "_flow_message", lambda *_args, **_kwargs: None)
    results = []
    monkeypatch.setattr(tui, "_control_result", lambda _screen, title, lines: results.append((title, lines)))
    import lattice.cli.commands.workers as workers_cmd
    calls = []
    monkeypatch.setattr(
        workers_cmd, "remove_worker_safely",
        lambda hostname, *, ask_confirmation, output: calls.append((hostname, ask_confirmation)) or output("securely removed") or 0,
    )

    tui._remove_worker_flow(object())
    assert calls == [("worker-node", False)]
    assert results[-1][0] == "COMPUTER REMOVED"


def test_health_check_worker_uses_real_recheck_pipeline_hooks(monkeypatch):
    status = _status(worker_count=1)
    status.workers[0].update({"hostname": "worker-node", "status": "healthy"})
    choices = iter([2, None])
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: next(choices))
    requested = []
    monkeypatch.setattr(tui, "_request_worker_rechecks", lambda hosts: requested.append(list(hosts)) or {hosts[0]: 10})
    monkeypatch.setattr(
        tui, "_wait_for_worker_checks",
        lambda _screen, _base: {"worker-node": {"severity": "ok", "message": "Health check for worker-node: healthy"}},
    )
    shown = []
    monkeypatch.setattr(tui, "_control_result", lambda _screen, title, lines: shown.append((title, lines)))

    tui._health_check_flow(object(), status, None)
    assert requested == [["worker-node"]]
    assert shown[0][0] == "HEALTH CHECK — worker-node"
    assert any("HEALTHY" in line for line in shown[0][1])


def test_reset_flow_requires_key_and_exact_confirmation_inside_tui(monkeypatch, tmp_path):
    db = tmp_path / "reset.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE workers (hostname TEXT, removed_at TEXT)")
    conn.execute("INSERT INTO workers VALUES ('backup-node', NULL)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(tui, "get_db_connection", lambda: sqlite3.connect(db))
    monkeypatch.setattr(
        tui, "load_config",
        lambda: SimpleNamespace(master=SimpleNamespace(master_key="secret")),
    )
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: 0)
    entries = iter(["secret", "RESET LATTICE"])
    monkeypatch.setattr(tui, "_control_text_input", lambda *_args, **_kwargs: next(entries))
    monkeypatch.setattr(tui, "_flow_message", lambda *_args, **_kwargs: None)
    shown = []
    monkeypatch.setattr(tui, "_control_result", lambda _screen, title, lines: shown.append((title, lines)))
    import lattice.cli.commands.wipe as wipe_cmd
    calls = []
    monkeypatch.setattr(wipe_cmd, "perform_wipe", lambda *, output: calls.append(True) or output("done") or 0)

    assert tui._reset_lattice_flow(object()) is True
    assert calls == [True]
    assert shown[-1][0] == "LATTICE RESET COMPLETE"



def test_perform_wipe_clears_current_fleet_runtime_schema(monkeypatch, tmp_path):
    from lattice.core.migrations import run_migrations
    import lattice.cli.commands.wipe as wipe_cmd

    db = tmp_path / "wipe-current.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)
    conn.execute(
        "INSERT INTO fleet_nodes(node_id, hostname, role, main_user, main_uid, main_gid, membership_state) "
        "VALUES ('master-node', 'master-node', 'master', 'masteruser', 1000, 1000, 'active')"
    )
    conn.execute(
        "INSERT INTO fleet_state(id, fleet_id, generation, manifest, signature, signing_public_key) "
        "VALUES (1, 'fleet-1', 1, '{}', 'sig', 'pub')"
    )
    conn.execute("INSERT INTO fleet_settings(key, value) VALUES ('example', 'value')")
    conn.execute("INSERT INTO mount_state(peer_node_id, state) VALUES ('peer', 'mounted')")
    conn.execute(
        "INSERT INTO shell_connection_history(peer_node_id, hostname, event_type, occurred_at) "
        "VALUES ('peer', 'backup-node', 'connected', '2026-09-01T00:00:00+00:00')"
    )
    conn.execute("INSERT INTO peer_routes(node_id, ip) VALUES ('master-node', '10.77.0.200')")
    conn.commit()
    conn.close()

    def open_db():
        c = sqlite3.connect(db)
        c.execute("PRAGMA foreign_keys=ON")
        return c

    monkeypatch.setattr(wipe_cmd, "get_db_connection", open_db)
    monkeypatch.setattr("lattice.wizard.lifecycle.current_role", lambda: "master")
    messages = []
    assert wipe_cmd.perform_wipe(output=messages.append) == 0

    conn = open_db()
    tables = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )]
    remaining = {
        table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in tables
    }
    conn.close()
    assert all(count == 0 for count in remaining.values()), remaining


def test_settings_help_is_code_grounded_and_hides_unenforced_connection_lifetime():
    from lattice.core.config import LatticeConfig
    config = LatticeConfig()

    network = dict((path, (label, desc, unit)) for name, items in tui._SETTINGS_CATEGORIES if name == "Network & Health" for path, label, desc, unit in items)
    advanced_paths = [path for name, items in tui._SETTINGS_CATEGORIES if name == "Advanced" for path, _label, _desc, _unit in items]

    assert network["wire_format.max_retry_attempts"][0] == "Network Attempt Limit"
    assert "including the first attempt" in " ".join(tui._setting_help("wire_format.max_retry_attempts", config))
    assert "wire_format.max_connection_lifetime_seconds" not in advanced_paths
    assert tui._format_setting_value(300, "seconds") == "5 minutes"
    assert tui._format_setting_value(2.0, "seconds") == "2 seconds"


def test_file_retry_settings_reject_initial_delay_above_maximum():
    from lattice.core.config import LatticeConfig
    import pytest

    config = LatticeConfig()
    with pytest.raises(Exception, match="Initial file retry delay"):
        tui._validated_config_update(config, "file_access.retry_initial_seconds", "500")


def test_autoheal_helpers_keep_worker_opt_in_independent(monkeypatch):
    import lattice.core.config as config_module

    calls = []
    monkeypatch.setattr(
        config_module,
        "set_config_value",
        lambda key, value: calls.append((key, value)),
    )

    tui._set_autoheal_mode("automatic")
    tui._set_worker_autoheal(1, True)
    tui._set_worker_autoheal(2, False)

    assert calls == [
        ("autoheal.mode", "automatic"),
        ("autoheal.enabled.1", "true"),
        ("autoheal.enabled.2", "false"),
    ]


def test_autoheal_worker_rows_read_individual_worker_state(
    monkeypatch, tmp_path
):
    import lattice.core.config as config_module

    db = tmp_path / "autoheal-workers.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE workers "
        "(id INTEGER PRIMARY KEY, hostname TEXT, removed_at TEXT)"
    )
    conn.execute(
        "INSERT INTO workers VALUES (1, 'worker-node', NULL)"
    )
    conn.execute(
        "INSERT INTO workers VALUES (2, 'backup-node', NULL)"
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        tui,
        "get_db_connection",
        lambda: sqlite3.connect(db),
    )
    values = {
        "autoheal.enabled.1": "true",
        "autoheal.enabled.2": None,
    }
    monkeypatch.setattr(
        config_module,
        "get_config_value",
        lambda key: values.get(key),
    )

    assert tui._autoheal_worker_rows() == [
        (2, "backup-node", False),
        (1, "worker-node", True),
    ]


def test_settings_dispatches_autoheal_to_dedicated_tui(monkeypatch):
    choices = iter([1, None])
    called = []

    monkeypatch.setattr(
        tui,
        "_control_menu",
        lambda *_args, **_kwargs: next(choices),
    )
    monkeypatch.setattr(
        tui,
        "_autoheal_settings_flow",
        lambda *_args: called.append("autoheal"),
    )

    tui._settings_flow(object())

    assert called == ["autoheal"]


def _worker_dashboard_status(*, hosted=True):
    target_rows = []
    if hosted:
        target_rows = [{
            "target_uuid": "generic-target",
            "present": True,
            "health": "healthy",
            "mountpoint": "/mnt/backup",
            "total_bytes": 1024 ** 4,
            "free_bytes": 600 * 1024 ** 3,
        }]
    return tui.LatticeStatus(
        role="worker",
        master_hostname="master-node",
        master_ip="10.77.0.200",
        daemon_status="running",
        uptime="2h 10m",
        version="0.1.0",
        workers=[],
        alerts=[],
        health={
            "worker": {
                "hostname": "worker-node",
                "node_id": "worker-id",
                "master_hostname": "master-node",
                "master_ip": "10.77.0.200",
                "overall": "healthy",
                "services": {
                    "lattice_core": "healthy",
                    "network": "healthy",
                    "fleet_sync": "healthy",
                    "mounts": "healthy",
                    "trusted_shell": "healthy",
                    "backup": "healthy",
                },
                "fleet_generation": 29,
                "file_generation": 29,
                "shell_generation": 29,
                "in_sync": True,
                "mounts": [
                    {"hostname": "master-node", "state": "mounted"},
                    {"hostname": "backup-node", "state": "mounted"},
                ],
                "shell_connections": [
                    {"hostname": "master-node", "state": "connected"},
                    {"hostname": "backup-node", "state": "connected"},
                ],
                "backup_jobs": [{
                    "job_uuid": "job-uuid",
                    "enabled": 1,
                    "paused": 0,
                    "source_path": "/home/workeruser",
                    "friendly_name": "Backup Drive",
                    "target_type": "remote_storage",
                    "host_node_id": "backup-node-id",
                    "observation": {
                        "state": "healthy",
                        "last_result": "successful",
                        "last_success_at": "2026-09-05T01:00:00+00:00",
                        "failure_streak": 0,
                    },
                }],
                "hosted_targets": target_rows,
            }
        },
    )


def test_worker_full_dashboard_is_role_correct(monkeypatch):
    _disable_curses(monkeypatch)
    screen = FakeScreen([(40, 120)], [ord("q")])

    result = tui.show_re_run_menu(screen, _worker_dashboard_status(hosted=True))
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)

    assert result == 6
    assert "LATTICE WORKER" in visible
    assert "MASTER CONNECTION" in visible
    assert "master-node" in visible
    assert "PEER CONNECTIONS" in visible
    assert "backup-node" in visible
    assert "SYNCHRONIZATION" in visible
    assert "IN SYNC" in visible
    assert "BACKUP STORAGE HOSTED HERE" in visible
    assert "HEALTHY" in visible
    assert "Add Computer" not in visible
    assert "Remove Computer" not in visible
    assert "Reset Lattice" not in visible
    assert "Auto-Heal" not in visible


def test_worker_compact_dashboard_keeps_core_semantics(monkeypatch):
    _disable_curses(monkeypatch)
    screen = FakeScreen([(24, 80)], [ord("q")])

    result = tui.show_re_run_menu(screen, _worker_dashboard_status(hosted=False))
    visible = "\n".join(text for _y, _x, text, _args in screen.writes)

    assert result == 6
    assert "LATTICE — WORKER" in visible
    assert "MASTER" in visible
    assert "LOCAL HEALTH" in visible
    assert "PEERS" in visible
    assert "SYNC" in visible
    assert "Backup" in visible
    assert "master-node" in visible
    assert "backup-node" in visible
    assert "BACKUP STORAGE" not in visible
    assert "[7]Exit" in visible
    assert "Add Computer" not in visible
    assert "Remove Computer" not in visible
    assert "Reset Lattice" not in visible
