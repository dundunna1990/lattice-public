import sqlite3

import pytest

from lattice.core.config import (
    LatticeConfig,
    get_config_value,
    reconcile_config,
    set_config_value,
)
from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations


def _db(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(path))
    conn = sqlite3.connect(path)
    run_migrations(conn)
    conn.close()
    return path


def test_reconcile_purges_static_and_secret_config_but_preserves_runtime_state(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    conn = get_db_connection()
    conn.executemany(
        "INSERT INTO config (key, value) VALUES (?, ?)",
        [
            ("master.master_key", "secret-one"),
            ("master.api_token", "secret-two"),
            ("master.telegram_secret", "secret-three"),
            ("master.telegram_token", "secret-four"),
            ("master.ip", "10.77.0.200"),
            ("wire_format.port", "9999"),
            ("autoheal.mode", "automatic"),
            ("autoheal.enabled.7", "true"),
            ("health.recheck.7", "true"),
            ("auto_heal.pause_until", "2030-01-01T00:00:00+00:00"),
        ],
    )
    conn.commit()
    conn.close()

    reconcile_config(LatticeConfig())

    conn = get_db_connection()
    rows = dict(conn.execute("SELECT key, value FROM config").fetchall())
    conn.close()
    assert rows == {
        "autoheal.mode": "automatic",
        "autoheal.enabled.7": "true",
        "health.recheck.7": "true",
        "auto_heal.pause_until": "2030-01-01T00:00:00+00:00",
    }


def test_runtime_config_access_rejects_static_secret_and_malformed_namespaces(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    for key in (
        "master.api_token",
        "master.master_key",
        "master.telegram_token",
        "wire_format.port",
        "autoheal.enabled.secret",
        "autoheal.enabled.0",
        "health.recheck.master.api_token",
    ):
        with pytest.raises(ValueError, match="not permitted"):
            get_config_value(key)
        with pytest.raises(ValueError, match="not permitted"):
            set_config_value(key, "value")


def test_runtime_config_access_accepts_only_explicit_runtime_state(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    values = {
        "autoheal.mode": "automatic",
        "auto_heal.pause_until": "2030-01-01T00:00:00+00:00",
        "autoheal.enabled.42": "true",
        "health.recheck.42": "true",
    }
    for key, value in values.items():
        set_config_value(key, value)
        assert get_config_value(key) == value
