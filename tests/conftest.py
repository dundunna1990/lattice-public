"""Test conftest — sets up isolated test environment.

Critical: env vars (LATTICE_CONFIG_PATH, LATTICE_TOKEN_PATH, LATTICE_DB_PATH)
are set at MODULE LEVEL (not in a fixture) because some test code reads the
config at import time. After the F481/F482 chmod 0640 lockdown, the test user
(masteruser) cannot read /etc/lattice/* directly, so we must redirect everything to
a temp dir the test user owns.
"""
import os
import shutil
import socket
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# ===== Set up test environment BEFORE any other code imports =====
TEST_DIR = Path(tempfile.mkdtemp(prefix="lattice-test-"))
TOKENS_DIR = TEST_DIR / "tokens"
TOKENS_DIR.mkdir()

# Test config file
TEST_CONFIG_PATH = TEST_DIR / "lattice.toml"
TEST_CONFIG_PATH.write_text("""[master]
ip = "127.0.0.1"
api_port = 8080
api_token = "test-token-not-secret"
master_key = "test-master-key"

[daemon]
log_level = "INFO"
dry_run = false

[wire_format]
port = 9999
""")

# Test token file (matches what worker_app.py expects: {hostname}.token)
TEST_TOKEN_PATH = TOKENS_DIR / f"{socket.gethostname()}.token"
TEST_TOKEN_PATH.write_text("test-token-not-secret")

# Test DB path
TEST_DB_PATH = TEST_DIR / "test.db"

# Set env vars BEFORE any code can import
os.environ["LATTICE_CONFIG_PATH"] = str(TEST_CONFIG_PATH)
os.environ["LATTICE_TOKEN_PATH"] = str(TEST_TOKEN_PATH)
os.environ["LATTICE_DB_PATH"] = str(TEST_DB_PATH)
os.environ["LATTICE_HEAL_AUDIT_LOG_PATH"] = str(TEST_DIR / "heal_audit.log")
os.environ["LATTICE_ADDRESS_POOL_PATH"] = str(TEST_DIR / "address-pool.json")
os.environ["LATTICE_FLEET_CACHE_PATH"] = str(TEST_DIR / "fleet-manifest.json")


@pytest.fixture(scope="session", autouse=True)
def lattice_db():
    """Create a fresh, fully-migrated test DB and seed test data."""
    db_path = str(TEST_DB_PATH)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    from lattice.core.migrations import run_migrations
    run_migrations(conn)

    # Seed test worker so unit tests that look up worker_id=1 pass
    recent = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()  # H8: aware UTC
    conn.execute(
        """INSERT OR IGNORE INTO workers
           (id, hostname, status, ssh_host_key_fingerprint, last_heartbeat_at, ssh_user, ip)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (1, "test-worker", "healthy", "SHA256:test-fixture-fingerprint", recent, "testuser", "127.0.0.1"),
    )
    # Seed test service so unit tests that look up services for worker_id=1 pass.
    conn.execute(
        """INSERT OR IGNORE INTO services
           (name, worker_id, type, status)
           VALUES (?, ?, ?, ?)""",
        ("test-service", 1, "systemd", "active"),
    )
    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    if os.path.exists(db_path):
        os.remove(db_path)
    for ext in ("-wal", "-shm", "-journal"):
        p = Path(db_path + ext)
        if p.exists():
            p.unlink()
    shutil.rmtree(TEST_DIR, ignore_errors=True)
