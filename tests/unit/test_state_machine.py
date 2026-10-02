import pytest
from datetime import datetime
from lattice.master.state_machine import WorkerState, update_worker_state, get_worker_state, set_worker_disabled
from lattice.core.db import get_db_connection

@pytest.fixture(autouse=True)
def reset_worker():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE workers SET status = 'healthy', failure_count = 0, ssh_host_key_fingerprint = 'fingerprint123', last_heartbeat_at = datetime('now') WHERE id = 1")
    conn.commit()

def test_initial_state():
    # Set to unknown
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE workers SET status = 'unknown' WHERE id = 1")
    conn.commit()
    state = get_worker_state(1)
    assert state == WorkerState.UNKNOWN

def test_first_success_moves_to_healthy():
    new_state = update_worker_state(1, True)
    assert new_state == WorkerState.HEALTHY
    state = get_worker_state(1)
    assert state == WorkerState.HEALTHY

def test_one_failure_moves_to_degraded():
    new_state = update_worker_state(1, False)
    assert new_state == WorkerState.DEGRADED
    state = get_worker_state(1)
    assert state == WorkerState.DEGRADED

def test_three_failures_moves_to_down():
    update_worker_state(1, False)  # -> Degraded
    update_worker_state(1, False)  # -> Degraded (still)
    new_state = update_worker_state(1, False)  # -> Down
    assert new_state == WorkerState.DOWN
    state = get_worker_state(1)
    assert state == WorkerState.DOWN

def test_healthy_check_resets_state():
    update_worker_state(1, False)
    update_worker_state(1, False)
    update_worker_state(1, False)  # now Down
    new_state = update_worker_state(1, True)
    assert new_state == WorkerState.HEALTHY
    state = get_worker_state(1)
    assert state == WorkerState.HEALTHY

def test_disabled_worker_does_not_transition():
    set_worker_disabled(1, True)
    state = get_worker_state(1)
    assert state == WorkerState.DISABLED
    new_state = update_worker_state(1, True)
    assert new_state == WorkerState.DISABLED
    state = get_worker_state(1)
    assert state == WorkerState.DISABLED
    set_worker_disabled(1, False)
    state = get_worker_state(1)
    assert state == WorkerState.UNKNOWN

def test_failure_count_resets_on_success():
    update_worker_state(1, False)
    update_worker_state(1, False)
    update_worker_state(1, True)  # success resets
    # now two failures should still be degraded, not down
    update_worker_state(1, False)
    update_worker_state(1, False)
    state = get_worker_state(1)
    assert state == WorkerState.DEGRADED
