import lattice.core.db
"""
Unit tests for event and alert storage.
"""
import pytest
import sqlite3
from datetime import datetime, timedelta, timezone
from lattice.core.events import (
    acknowledge_alert,
    create_alert,
    get_active_alerts,
    log_event,
    resolve_alert,
    resolve_worker_alerts_after_recovery,
    sync_network_reconcile_alert,
    resolve_legacy_master_self_check_alerts,
    sync_master_self_check_alert,
)
# from lattice.core.db import get_db_connection

@pytest.fixture(autouse=True)
def setup_db():
    """Create a fresh in‑memory database for each test, keeping a connection alive."""
    import sqlite3
    import lattice.core.events
    import lattice.core.db

    # Shared in‑memory database URI
    db_uri = "file:testdb?mode=memory&cache=shared"

    # Create a persistent connection that will stay open for the whole test
    persistent_conn = sqlite3.connect(db_uri, uri=True)
    persistent_conn.row_factory = sqlite3.Row

    def patched_get_db_connection():
        # Return a new connection to the same shared DB
        conn = sqlite3.connect(db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    # Patch get_db_connection in both modules
    original_get_db = lattice.core.db.get_db_connection
    lattice.core.db.get_db_connection = patched_get_db_connection
    lattice.core.events.get_db_connection = patched_get_db_connection

    # Create tables using the persistent connection
    cursor = persistent_conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workers (
            id INTEGER PRIMARY KEY,
            hostname TEXT NOT NULL UNIQUE
        )
    """)
    cursor.execute("INSERT OR IGNORE INTO workers (id, hostname) VALUES (1, 'test-worker')")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            worker_id INTEGER,
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            FOREIGN KEY (worker_id) REFERENCES workers(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            worker_id INTEGER,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            trigger_event_id INTEGER,
            fired_at TEXT NOT NULL,
            acked_at TEXT,
            resolved_at TEXT,
            resolution_event_id INTEGER,
            FOREIGN KEY (worker_id) REFERENCES workers(id)
        )
    """)
    persistent_conn.commit()

    yield

    # Clean up: close persistent connection and restore original
    persistent_conn.close()
    lattice.core.db.get_db_connection = original_get_db
    lattice.core.events.get_db_connection = original_get_db
def test_log_event():
    """Logging an event should create a record."""
    event_id = log_event(1, "test.event", "info", "Test event", {"key": "value"})
    conn = lattice.core.db.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    assert row is not None
    assert row[2] == 1  # worker_id
    assert row[3] == "test.event"

def test_create_alert():
    """Creating an alert should store it and return an ID."""
    event_id = log_event(1, "test.alert", "error", "Something went wrong")
    alert_id = create_alert(1, "error", "Test Alert", "This is a test", event_id)
    assert alert_id is not None
    active = get_active_alerts()
    assert len(active) == 1
    assert active[0]["title"] == "Test Alert"
    assert active[0]["worker"] == "test-worker"


def test_master_alert_is_labeled_as_master_in_dashboard_data():
    event_id = log_event(None, "test.master", "warn", "Master needs a check")
    create_alert(None, "warn", "Master Alert", "This is a test", event_id)

    active = get_active_alerts()

    assert active[0]["worker"] == "Master"

def test_dedup():
    """Duplicate alerts within the dedup window should be suppressed."""
    event_id1 = log_event(1, "test.alert", "error", "Something went wrong")
    alert1 = create_alert(1, "error", "Test Alert", "This is a test", event_id1)
    assert alert1 is not None
    # Second alert with same title and worker should be dedup'd
    event_id2 = log_event(1, "test.alert", "error", "Something went wrong again")
    alert2 = create_alert(1, "error", "Test Alert", "This is a test", event_id2)
    assert alert2 is None  # dedup'd
    active = get_active_alerts()
    assert len(active) == 1


def test_master_alert_without_a_worker_is_stored_and_deduplicated():
    event_id = log_event(None, "autoheal.master_detected", "warn", "Master socket failed")
    first = create_alert(None, "warn", "Lattice master problem", "Socket check failed", event_id)
    second = create_alert(None, "warn", "Lattice master problem", "Socket check failed", event_id)

    assert first is not None
    assert second is None
    assert get_active_alerts()[0]["title"] == "Lattice master problem"

def test_resolve_alert():
    """Resolving an alert should mark it as resolved."""
    event_id = log_event(1, "test.alert", "error", "Something went wrong")
    alert_id = create_alert(1, "error", "Test Alert", "This is a test", event_id)
    assert alert_id is not None
    result = resolve_alert(alert_id)
    assert result is True
    active = get_active_alerts()
    assert len(active) == 0
    # Can't resolve again
    result2 = resolve_alert(alert_id)
    assert result2 is False


def test_acknowledgement_suppresses_repeats_without_resolving():
    event_id = log_event(1, "autoheal.failed", "error", "Restart failed")
    alert_id = create_alert(1, "error", "Repair failed", "Restart failed", event_id)
    assert acknowledge_alert(alert_id) is True
    conn = lattice.core.db.get_db_connection()
    conn.execute(
        "UPDATE alerts SET fired_at = ? WHERE id = ?",
        ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), alert_id),
    )
    conn.commit()
    conn.close()

    repeat_event = log_event(1, "autoheal.failed", "error", "Restart failed again")
    assert create_alert(1, "error", "Repair failed", "Again", repeat_event) is None
    assert len(get_active_alerts()) == 1


def test_verified_recovery_resolves_repair_and_protected_alerts_only():
    repair_event = log_event(1, "autoheal.failed", "error", "Restart failed")
    protected_event = log_event(
        1, "autoheal.protected_issue", "warn", "Protected SSH was unreachable"
    )
    other_event = log_event(1, "security.audit", "error", "Audit problem")
    create_alert(1, "error", "Repair failed", "Restart failed", repair_event)
    create_alert(
        1, "warn", "Protected system problem: SSH", "SSH unavailable", protected_event
    )
    create_alert(1, "error", "Audit unavailable", "Audit problem", other_event)

    assert resolve_worker_alerts_after_recovery(1) == 2
    assert [alert["title"] for alert in get_active_alerts()] == ["Audit unavailable"]

def test_worker_network_reconcile_alert_is_single_and_auto_resolves():
    first = sync_network_reconcile_alert(1, "test-worker", "repair_failed")
    second = sync_network_reconcile_alert(1, "test-worker", "repair_failed")
    assert first is not None
    assert second == first
    assert len(get_active_alerts()) == 1
    resolved = sync_network_reconcile_alert(1, "test-worker", "healthy")
    assert resolved == first
    assert get_active_alerts() == []


def test_master_network_reconcile_alert_is_single_and_auto_resolves():
    first = sync_network_reconcile_alert(None, "master-host", "unsafe_network")
    second = sync_network_reconcile_alert(None, "master-host", "unsafe_network")
    assert first is not None
    assert second == first
    active = get_active_alerts()
    assert len(active) == 1 and active[0]["worker"] == "Master"
    sync_network_reconcile_alert(None, "master-host", "repaired")
    assert get_active_alerts() == []


def test_active_alert_deduplicates_even_when_older_than_old_window():
    event_id = log_event(None, "autoheal.master_detected", "warn", "socket failed")
    first = create_alert(None, "warn", "Persistent incident", "failed", event_id)
    conn = lattice.core.db.get_db_connection()
    conn.execute(
        "UPDATE alerts SET fired_at=? WHERE id=?",
        ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(), first),
    )
    conn.commit(); conn.close()
    event2 = log_event(None, "autoheal.master_detected", "warn", "still failed")
    assert create_alert(None, "warn", "Persistent incident", "still failed", event2) is None
    assert len(get_active_alerts()) == 1


def test_master_self_check_component_is_single_and_auto_resolves():
    first = sync_master_self_check_alert("socket", "connection refused")
    second = sync_master_self_check_alert("socket", "still refused")
    assert first is not None and second == first
    assert len(get_active_alerts()) == 1
    assert sync_master_self_check_alert("socket", None) == first
    assert get_active_alerts() == []


def test_legacy_master_self_check_cleanup_preserves_unrelated_alerts():
    event1 = log_event(None, "autoheal.master_detected", "warn", "old socket fail")
    event2 = log_event(None, "autoheal.master_detected", "warn", "old db fail")
    other = log_event(None, "security.audit", "error", "security issue")
    create_alert(None, "warn", "Legacy one", "old", event1)
    create_alert(None, "warn", "Legacy two", "old", event2)
    create_alert(None, "error", "Security alert", "keep", other)
    assert resolve_legacy_master_self_check_alerts() == 2
    assert [a["title"] for a in get_active_alerts()] == ["Security alert"]


def test_audit_capacity_alert_escalates_without_duplicate():
    first = sync_master_self_check_alert(
        "audit_log", "75.0 MB", severity="warn"
    )
    assert first is not None
    active = get_active_alerts()
    assert len(active) == 1 and active[0]["severity"] == "warn"

    second = sync_master_self_check_alert(
        "audit_log", "90.0 MB", severity="error"
    )
    assert second == first
    active = get_active_alerts()
    assert len(active) == 1 and active[0]["severity"] == "error"

    assert sync_master_self_check_alert("audit_log", None) == first
    assert get_active_alerts() == []
