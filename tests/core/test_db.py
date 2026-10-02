import os
import sqlite3
import pytest
from pathlib import Path
from lattice.core.migrations import run_migrations
from lattice.core.db import get_db_connection
from lattice.core.db_recovery import (
    DatabaseRecoveryError,
    create_verified_backup,
    restore_verified_backup,
    verify_database,
)

def test_migrations_and_schema(tmp_path, monkeypatch):
    """Tests that migrations run cleanly and create all required tables."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db_path))

    # Run the migration engine
    conn = get_db_connection()
    run_migrations(conn)
    conn.close()

    # Connect and verify the schema
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cursor.fetchall()}

    expected_tables = {"workers", "events", "alerts", "services", "circuit_breaker_state", "healing_attempts", "config"}

    assert expected_tables.issubset(tables)
    conn.close()


def test_verified_database_backup_and_restore(
    tmp_path,
    monkeypatch,
):
    db_path = tmp_path / "state.sqlite"
    monkeypatch.setenv(
        "LATTICE_DB_PATH",
        str(db_path),
    )

    conn = get_db_connection()
    run_migrations(conn)

    conn.execute(
        """
        INSERT INTO workers (
            hostname,
            status
        )
        VALUES ('backup-worker', 'healthy')
        """
    )
    conn.commit()
    conn.close()

    assert verify_database(db_path) is True

    backup = create_verified_backup(
        db_path,
        tmp_path / "backups",
    )

    assert backup is not None
    assert verify_database(backup) is True

    db_path.write_bytes(
        b"definitely not sqlite"
    )

    assert verify_database(db_path) is False

    restore_verified_backup(
        backup,
        db_path,
    )

    assert verify_database(db_path) is True

    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT hostname
            FROM workers
            WHERE hostname = 'backup-worker'
            """
        ).fetchone()
    finally:
        conn.close()

    assert row == ("backup-worker",)

    preserved = list(
        tmp_path.glob(
            "state.sqlite.replaced-*"
        )
    )
    assert len(preserved) == 1


def test_corrupt_database_is_never_backed_up_as_good(
    tmp_path,
):
    db_path = tmp_path / "state.sqlite"
    db_path.write_bytes(
        b"not a sqlite database"
    )

    assert verify_database(db_path) is False

    with pytest.raises(
        DatabaseRecoveryError,
        match="corrupt state",
    ):
        create_verified_backup(
            db_path,
            tmp_path / "backups",
        )
