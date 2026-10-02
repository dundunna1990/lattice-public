import sqlite3

from lattice.core.config import LatticeConfig, reconcile_config
from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations


def test_future_static_config_keys_are_not_implicitly_mirrored(monkeypatch, tmp_path):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("LATTICE_DB_PATH", db_path)
    conn = sqlite3.connect(db_path)
    run_migrations(conn)
    conn.close()

    conn = get_db_connection()
    conn.executemany(
        "INSERT INTO config (key, value) VALUES (?, ?)",
        [
            ("wire_format.port", "9999"),
            ("master.api_token", "must-not-remain"),
            ("health.recheck.12", "true"),
        ],
    )
    conn.commit()
    conn.close()

    reconcile_config(LatticeConfig())

    conn = get_db_connection()
    rows = dict(conn.execute("SELECT key, value FROM config").fetchall())
    conn.close()
    assert rows == {"health.recheck.12": "true"}
