import pytest

from lattice.core.config import (
    LatticeConfig,
    load_config,
    reconcile_config,
    save_config,
)
from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations


def test_load_config_defaults(tmp_path, monkeypatch):
    fake_path = tmp_path / "does_not_exist.toml"
    config = load_config(str(fake_path))
    assert isinstance(config, LatticeConfig)
    assert config.master.ip == "127.0.0.1"
    assert config.daemon.poll_interval == 10
    assert config.daemon.dry_run is True


def test_reconcile_config_purges_static_config_but_keeps_runtime_state(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db_path))
    conn = get_db_connection()
    run_migrations(conn)
    conn.executemany(
        "INSERT INTO config (key, value) VALUES (?, ?)",
        [
            ("master.ip", "10.77.0.88"),
            ("daemon.dry_run", "False"),
            ("autoheal.mode", "automatic"),
        ],
    )
    conn.commit()
    conn.close()

    reconcile_config(LatticeConfig())

    conn = get_db_connection()
    rows = dict(conn.execute("SELECT key, value FROM config").fetchall())
    conn.close()
    assert rows == {"autoheal.mode": "automatic"}


def test_save_config_writes_valid_toml(tmp_path):
    config_path = tmp_path / "lattice.toml"
    config = LatticeConfig()
    config.master.ip = "10.77.0.88"
    config.daemon.dry_run = False
    save_config(config, str(config_path))

    loaded = load_config(str(config_path))
    assert loaded.master.ip == "10.77.0.88"
    assert loaded.daemon.dry_run is False


def test_save_config_enforces_production_owner_and_mode_when_root(tmp_path, monkeypatch):
    import lattice.core.config as config_module

    config_path = tmp_path / "lattice.toml"
    config_path.write_text("[daemon]\ndry_run = true\n")
    config_path.chmod(0o600)
    monkeypatch.setattr(config_module, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(config_module.os, "geteuid", lambda: 0)

    class Group:
        gr_gid = 4242

    calls = []
    monkeypatch.setattr("grp.getgrnam", lambda name: Group())
    monkeypatch.setattr(config_module.os, "chown", lambda path, uid, gid: calls.append((uid, gid)))

    config = LatticeConfig()
    save_config(config, str(config_path))

    assert calls == [(0, 4242)]
    assert config_path.stat().st_mode & 0o777 == 0o640


def test_retry_bounds_are_validated():
    with pytest.raises(ValueError, match="Initial network backoff"):
        LatticeConfig(
            wire_format={
                "retry_initial_backoff_ms": 3000,
                "retry_max_backoff_ms": 2000,
            }
        )

    with pytest.raises(ValueError, match="Initial file retry delay"):
        LatticeConfig(
            file_access={
                "retry_initial_seconds": 20,
                "retry_max_seconds": 10,
            }
        )
