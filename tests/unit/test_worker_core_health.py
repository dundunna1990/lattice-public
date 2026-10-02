from types import SimpleNamespace

from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations
from lattice.worker.health import HealthChecker


def _config(*, file_enabled=True, shell_enabled=True):
    return SimpleNamespace(
        file_access=SimpleNamespace(enabled=file_enabled),
        shell_access=SimpleNamespace(enabled=shell_enabled),
    )


def _db(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(path))
    conn = get_db_connection()
    run_migrations(conn)
    return conn


def test_core_health_is_healthy_when_core_channels_are_current(
    tmp_path, monkeypatch
):
    conn = _db(tmp_path, monkeypatch)
    conn.execute(
        "INSERT INTO shell_connection_state "
        "(peer_node_id, hostname, state) VALUES ('peer', 'master', 'connected')"
    )
    conn.commit()
    conn.close()
    checker = HealthChecker()
    monkeypatch.setattr(checker, "check_systemd_unit", lambda _unit: True)
    results = checker.check_core_components(
        config=_config(),
        fleet_generation=3,
        file_transport_generation=3,
        file_export_ok=True,
        shell_transport_generation=3,
        mount_observations=[{"state": "mounted"}],
    )
    assert {row["name"]: row["status"] for row in results} == {
        "fleet_sync": "healthy",
        "file_transport": "healthy",
        "file_export": "healthy",
        "mounts": "healthy",
        "shell_transport": "healthy",
        "trusted_shell": "healthy",
    }


def test_core_health_degrades_broken_mount_and_shell(tmp_path, monkeypatch):
    conn = _db(tmp_path, monkeypatch)
    conn.execute(
        "INSERT INTO shell_connection_state "
        "(peer_node_id, hostname, state) VALUES ('peer', 'master', 'unavailable')"
    )
    conn.commit()
    conn.close()
    checker = HealthChecker()
    monkeypatch.setattr(checker, "check_systemd_unit", lambda _unit: True)
    results = checker.check_core_components(
        config=_config(),
        fleet_generation=3,
        file_transport_generation=3,
        file_export_ok=True,
        shell_transport_generation=3,
        mount_observations=[{"state": "mount_problem"}],
    )
    statuses = {row["name"]: row["status"] for row in results}
    assert statuses["mounts"] == "unhealthy"
    assert statuses["trusted_shell"] == "unhealthy"


def test_paused_mount_and_disabled_channels_do_not_degrade(tmp_path, monkeypatch):
    conn = _db(tmp_path, monkeypatch)
    conn.close()
    checker = HealthChecker()
    monkeypatch.setattr(checker, "check_systemd_unit", lambda _unit: True)
    results = checker.check_core_components(
        config=_config(file_enabled=True, shell_enabled=False),
        fleet_generation=2,
        file_transport_generation=2,
        file_export_ok=True,
        shell_transport_generation=0,
        mount_observations=[{"state": "paused"}],
    )
    statuses = {row["name"]: row["status"] for row in results}
    assert statuses == {
        "fleet_sync": "healthy",
        "file_transport": "healthy",
        "file_export": "healthy",
        "mounts": "healthy",
    }


def test_core_health_degrades_when_home_export_bind_is_missing(tmp_path, monkeypatch):
    conn = _db(tmp_path, monkeypatch)
    conn.execute(
        "INSERT INTO shell_connection_state "
        "(peer_node_id, hostname, state) VALUES ('peer', 'master', 'connected')"
    )
    conn.commit()
    conn.close()
    checker = HealthChecker()
    monkeypatch.setattr(checker, "check_systemd_unit", lambda _unit: True)
    results = checker.check_core_components(
        config=_config(),
        fleet_generation=3,
        file_transport_generation=3,
        file_export_ok=False,
        shell_transport_generation=3,
        mount_observations=[{"state": "mounted"}],
    )
    statuses = {row["name"]: row["status"] for row in results}
    assert statuses["file_transport"] == "healthy"
    assert statuses["file_export"] == "unhealthy"


def test_core_health_degrades_when_dedicated_shell_sshd_is_down(tmp_path, monkeypatch):
    conn = _db(tmp_path, monkeypatch)
    conn.execute("INSERT INTO shell_connection_state (peer_node_id, hostname, state) VALUES ('peer', 'master', 'connected')")
    conn.commit(); conn.close()
    checker = HealthChecker()
    monkeypatch.setattr(checker, "check_systemd_unit", lambda unit: unit != "lattice-shell-sshd.service")
    results = checker.check_core_components(
        config=_config(), fleet_generation=3, file_transport_generation=3,
        file_export_ok=True, shell_transport_generation=3,
        mount_observations=[{"state": "mounted"}],
    )
    statuses = {row["name"]: row["status"] for row in results}
    assert statuses["shell_transport"] == "unhealthy"


def test_live_health_snapshot_degrades_when_backup_protection_is_unhealthy(monkeypatch):
    checker = HealthChecker()
    monkeypatch.setattr(checker, 'check_all', lambda: [{'name': 'sshd', 'status': 'healthy'}])
    monkeypatch.setattr(checker, 'check_core_components', lambda **kwargs: [])
    monkeypatch.setattr(
        'lattice.core.config.load_config',
        lambda: _config(file_enabled=False, shell_enabled=False),
    )
    monkeypatch.setattr(
        'lattice.file_access.sync.get_cached_fleet_generation', lambda: 1
    )
    monkeypatch.setattr(
        'lattice.file_access.observations.local_mount_observations', lambda: []
    )
    monkeypatch.setattr('lattice.file_access.identity.load_node_identity', lambda: None)
    monkeypatch.setattr(
        'lattice.backup.observations.local_backup_observations',
        lambda: [{'state': 'pending'}],
    )
    monkeypatch.setattr(
        'lattice.backup.observations.backup_service_status',
        lambda rows: 'unhealthy',
    )
    snapshot = checker.current_snapshot()
    assert snapshot['status'] == 'degraded'
    statuses = {row['name']: row['status'] for row in snapshot['services']}
    assert statuses['backup'] == 'unhealthy'
    assert statuses['lattice_core'] == 'healthy'
