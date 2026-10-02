import pytest
from datetime import datetime, timedelta
from unittest.mock import patch
from lattice.master.circuit_breaker import (
    CircuitBreaker,
    DEFAULT_THRESHOLD,
    DEFAULT_COOLDOWN_SECONDS,
    DEFAULT_PROBE_TIMEOUT,
)
from lattice.core.db import get_db_connection

def test_initial_state_closed():
    cb = CircuitBreaker(1, "restart")
    assert cb.is_open() is False

def test_failure_count_increments():
    cb = CircuitBreaker(1, "restart")
    for _ in range(DEFAULT_THRESHOLD - 1):
        cb.record_failure()
        assert cb.is_open() is False
    cb.record_failure()
    assert cb.is_open() is True

def test_success_resets_circuit():
    cb = CircuitBreaker(1, "restart")
    for _ in range(DEFAULT_THRESHOLD):
        cb.record_failure()
    assert cb.is_open() is True
    cb.record_success()
    assert cb.is_open() is False

def test_cooldown_moves_to_half_open():
    cb = CircuitBreaker(1, "restart")
    for _ in range(DEFAULT_THRESHOLD):
        cb.record_failure()
    assert cb.is_open() is True

    # Manually set opened_at to a past time in the DB
    conn = get_db_connection()
    cursor = conn.cursor()
    past_time = (datetime.utcnow() - timedelta(seconds=DEFAULT_COOLDOWN_SECONDS + 5)).isoformat()
    cursor.execute("UPDATE circuit_breaker_state SET opened_at = ? WHERE worker_id = 1 AND action = 'restart'", (past_time,))
    conn.commit()
    conn.close()

    # Now is_open should return False (half-open)
    assert cb.is_open() is False

def test_half_open_failure_reopens():
    cb = CircuitBreaker(1, "restart")
    for _ in range(DEFAULT_THRESHOLD):
        cb.record_failure()
    assert cb.is_open() is True

    conn = get_db_connection()
    cursor = conn.cursor()
    past_time = (datetime.utcnow() - timedelta(seconds=DEFAULT_COOLDOWN_SECONDS + 5)).isoformat()
    cursor.execute("UPDATE circuit_breaker_state SET opened_at = ? WHERE worker_id = 1 AND action = 'restart'", (past_time,))
    conn.commit()
    conn.close()

    # Should now be half-open (is_open False)
    assert cb.is_open() is False

    # A failure should reopen
    cb.record_failure()
    assert cb.is_open() is True

def test_half_open_success_closes():
    cb = CircuitBreaker(1, "restart")
    for _ in range(DEFAULT_THRESHOLD):
        cb.record_failure()
    assert cb.is_open() is True

    conn = get_db_connection()
    cursor = conn.cursor()
    past_time = (datetime.utcnow() - timedelta(seconds=DEFAULT_COOLDOWN_SECONDS + 5)).isoformat()
    cursor.execute("UPDATE circuit_breaker_state SET opened_at = ? WHERE worker_id = 1 AND action = 'restart'", (past_time,))
    conn.commit()
    conn.close()

    # Should be half-open
    assert cb.is_open() is False

    # A success should close
    cb.record_success()
    assert cb.is_open() is False

def test_half_open_allows_only_one_probe():
    """Two concurrent is_open() calls in half_open — only one returns False."""
    import threading
    cb = CircuitBreaker(2, "restart")
    # Force the circuit to half_open state with a fresh token
    conn = get_db_connection()
    cursor = conn.cursor()
    past = (datetime.utcnow() - timedelta(seconds=DEFAULT_COOLDOWN_SECONDS + 5)).isoformat()
    cursor.execute(
        "INSERT OR REPLACE INTO circuit_breaker_state "
        "(worker_id, action, state, failure_count, opened_at, half_open_at, half_open_token) "
        "VALUES (?, ?, 'half_open', 0, ?, ?, ?)",
        (2, "restart", past, datetime.utcnow().isoformat(), "test-token-123"),
    )
    conn.commit()
    conn.close()

    results = []
    lock = threading.Lock()
    def attempt():
        result = cb.is_open()
        with lock:
            results.append(result)
    threads = [threading.Thread(target=attempt) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one caller should have won the probe (is_open() == False)
    false_count = sum(1 for r in results if r is False)
    assert false_count == 1, f"Expected exactly 1 probe winner, got {false_count}: {results}"


def test_half_open_probe_failure_reopens():
    """If the probe caller calls record_failure, the circuit reopens."""
    cb = CircuitBreaker(3, "restart")
    # Force into half_open
    conn = get_db_connection()
    cursor = conn.cursor()
    past = (datetime.utcnow() - timedelta(seconds=DEFAULT_COOLDOWN_SECONDS + 5)).isoformat()
    cursor.execute(
        "INSERT OR REPLACE INTO circuit_breaker_state "
        "(worker_id, action, state, failure_count, opened_at, half_open_at, half_open_token) "
        "VALUES (?, ?, 'half_open', 0, ?, ?, ?)",
        (3, "restart", past, datetime.utcnow().isoformat(), "test-token-456"),
    )
    conn.commit()
    conn.close()
    # Win the probe
    assert cb.is_open() is False
    # Probe fails
    cb.record_failure()
    # Circuit reopens
    assert cb.is_open() is True


def test_stale_half_open_probe_is_reclaimed_by_exactly_one_caller():
    """A crashed half-open probe becomes reclaimable after its timeout."""
    import threading

    cb = CircuitBreaker(4, "restart")
    stale_started = (
        datetime.utcnow() - timedelta(seconds=DEFAULT_PROBE_TIMEOUT + 5)
    ).isoformat()

    conn = get_db_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO circuit_breaker_state
               (worker_id, action, state, failure_count, opened_at,
                half_open_at, half_open_token, probe_started_at)
               VALUES (?, ?, 'half_open', 0, ?, ?, NULL, ?)""",
            (
                4,
                "restart",
                stale_started,
                stale_started,
                stale_started,
            ),
        )
        conn.commit()
    finally:
        conn.close()

    results = []
    lock = threading.Lock()

    def attempt():
        result = cb.is_open()
        with lock:
            results.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = sum(result is False for result in results)
    assert winners == 1, f"Expected exactly 1 stale-probe winner, got {winners}: {results}"

    # The winner refreshed probe_started_at, so an immediate caller is blocked.
    assert cb.is_open() is True


def test_new_circuit_timestamps_are_timezone_aware_utc():
    cb = CircuitBreaker(9, "restart")
    for _ in range(DEFAULT_THRESHOLD):
        cb.record_failure()
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT opened_at FROM circuit_breaker_state WHERE worker_id=? AND action=?",
            (9, "restart"),
        ).fetchone()
    finally:
        conn.close()
    parsed = datetime.fromisoformat(row["opened_at"])
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timedelta(0)
