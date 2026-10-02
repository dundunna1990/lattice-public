import pytest
from datetime import datetime, timedelta
from lattice.core.db import get_db_connection
from lattice.healing.signals import (
    get_worker_identity_status,
    get_health_signals,
    should_heal,
    get_required_signals_count
)

def test_identity_success():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE workers SET ssh_host_key_fingerprint = 'fingerprint123', last_heartbeat_at = datetime('now') WHERE id = 1")
    conn.commit()
    conn.close()
    assert get_worker_identity_status(1) is True

def test_identity_no_host_key():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE workers SET ssh_host_key_fingerprint = NULL, last_heartbeat_at = datetime('now') WHERE id = 1")
    conn.commit()
    result = get_worker_identity_status(1)
    assert result is False

def test_identity_stale_heartbeat_does_not_invalidate_pinned_identity():
    conn = get_db_connection()
    cursor = conn.cursor()
    stale_time = (datetime.utcnow() - timedelta(minutes=10)).isoformat()
    cursor.execute("UPDATE workers SET last_heartbeat_at = ?, ssh_host_key_fingerprint = 'fingerprint123' WHERE id = 1", (stale_time,))
    conn.commit()
    conn.close()
    assert get_worker_identity_status(1) is True


def test_identity_missing_heartbeat_does_not_invalidate_pinned_identity():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE workers SET last_heartbeat_at = NULL, ssh_host_key_fingerprint = 'fingerprint123' WHERE id = 1")
    conn.commit()
    conn.close()
    assert get_worker_identity_status(1) is True

def test_get_health_signals():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO events (timestamp, worker_id, type, severity, message) VALUES (datetime('now'), 1, 'health_check.failed', 'error', 'test')")
    cursor.execute("UPDATE services SET status = 'inactive', last_reported_at = datetime('now') WHERE worker_id = 1 AND name = 'test-service'")
    conn.commit()
    signals = get_health_signals(1, 'test-service')
    assert len(signals) >= 2

def test_should_heal_identity_fail():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE workers SET ssh_host_key_fingerprint = NULL WHERE id = 1")
    conn.commit()
    result = should_heal(1, 'test-service')
    assert result is False

def test_should_heal_with_identity_and_signals():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("UPDATE workers SET ssh_host_key_fingerprint = 'fingerprint123', last_heartbeat_at = datetime('now') WHERE id = 1")
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('autoheal.enabled.1', 'true')")
    cursor.execute("UPDATE services SET status = 'inactive', last_reported_at = datetime('now') WHERE worker_id = 1 AND name = 'test-service'")
    cursor.execute("DELETE FROM events")
    cursor.execute("INSERT INTO events (timestamp, worker_id, type, severity, message) VALUES (datetime('now'), 1, 'health_check.failed', 'error', 'test')")
    cursor.execute("INSERT INTO events (timestamp, worker_id, type, severity, message) VALUES (datetime('now'), 1, 'health_check.failed', 'error', 'test')")
    conn.commit()
    conn.close()
    result = should_heal(1, 'test-service')
    assert result is True

def test_should_heal_not_enough_signals():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("UPDATE workers SET ssh_host_key_fingerprint = 'fingerprint123', last_heartbeat_at = datetime('now') WHERE id = 1")
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('autoheal.enabled.1', 'true')")
    # Ensure the service is active so it doesn't contribute a failure signal
    cursor.execute("UPDATE services SET status = 'active', last_reported_at = datetime('now') WHERE worker_id = 1 AND name = 'test-service'")
    cursor.execute("DELETE FROM events")
    cursor.execute("INSERT INTO events (timestamp, worker_id, type, severity, message) VALUES (datetime('now'), 1, 'health_check.failed', 'error', 'test')")
    conn.commit()
    result = should_heal(1, 'test-service')
    assert result is False

def test_debug_should_heal():
    """Debug helper – prints conditions."""
    from lattice.core.config import get_config_value
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
    cursor.execute("UPDATE workers SET ssh_host_key_fingerprint = 'fingerprint123', last_heartbeat_at = datetime('now') WHERE id = 1")
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('autoheal.enabled.1', 'true')")
    cursor.execute("UPDATE services SET status = 'inactive', last_reported_at = datetime('now') WHERE worker_id = 1 AND name = 'test-service'")
    cursor.execute("DELETE FROM events")
    cursor.execute("INSERT INTO events (timestamp, worker_id, type, severity, message) VALUES (datetime('now'), 1, 'health_check.failed', 'error', 'test')")
    cursor.execute("INSERT INTO events (timestamp, worker_id, type, severity, message) VALUES (datetime('now'), 1, 'health_check.failed', 'error', 'test')")
    conn.commit()
    conn.close()

    print("\n=== DEBUG ===")
    identity = get_worker_identity_status(1)
    print(f"Identity verified: {identity}")
    signals = get_health_signals(1, 'test-service')
    print(f"Signals count: {len(signals)}")
    required = get_required_signals_count()
    print(f"Required signals: {required}")
    opt_in = get_config_value('autoheal.enabled.1')
    print(f"Opt-in value: {opt_in}")

    result = should_heal(1, 'test-service')
    print(f"Final should_heal result: {result}")
    assert result is True
