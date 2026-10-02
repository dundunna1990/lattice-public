"""Verify bootstrap behavior without the shared seeded unit-test worker."""

from pathlib import Path
import os
import sqlite3
import subprocess
import sys


def test_fresh_database_bootstrap_starts_empty(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "fresh.sqlite"

    env = os.environ.copy()
    env["LATTICE_DB_PATH"] = str(
        db_path
    )

    program = """
import os
import sqlite3

from lattice.core.bootstrap_prepare import run_db_migrations

run_db_migrations()

conn = sqlite3.connect(
    os.environ["LATTICE_DB_PATH"]
)

workers = conn.execute(
    "SELECT COUNT(*) FROM workers"
).fetchone()[0]

services = conn.execute(
    "SELECT COUNT(*) FROM services"
).fetchone()[0]

conn.close()

assert workers == 0, workers
assert services == 0, services
"""

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
        ],
        cwd="/",
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, (
        result.stdout + result.stderr
    )

    assert db_path.exists()

    conn = sqlite3.connect(
        db_path
    )

    assert conn.execute(
        "SELECT COUNT(*) FROM workers"
    ).fetchone()[0] == 0

    assert conn.execute(
        "SELECT COUNT(*) FROM services"
    ).fetchone()[0] == 0

    conn.close()
