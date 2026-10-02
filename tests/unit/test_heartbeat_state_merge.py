from lattice.master.state_machine import (
    WorkerState,
    heartbeat_worker_target_state,
)


def test_degraded_heartbeat_can_lower_healthy_worker():
    assert heartbeat_worker_target_state(
        "healthy", 0, "degraded"
    ) == WorkerState.DEGRADED


def test_healthy_heartbeat_can_clear_service_only_degraded_state():
    assert heartbeat_worker_target_state(
        "degraded", 0, "healthy"
    ) == WorkerState.HEALTHY


def test_healthy_heartbeat_cannot_clear_connectivity_degradation():
    assert heartbeat_worker_target_state(
        "degraded", 1, "healthy"
    ) == WorkerState.DEGRADED


def test_heartbeat_cannot_clear_down():
    assert heartbeat_worker_target_state(
        "down", 3, "healthy"
    ) == WorkerState.DOWN


def test_heartbeat_cannot_change_disabled():
    assert heartbeat_worker_target_state(
        "disabled", 0, "degraded"
    ) == WorkerState.DISABLED


def test_heartbeat_does_not_promote_unknown_to_healthy():
    assert heartbeat_worker_target_state(
        "unknown", 0, "healthy"
    ) == WorkerState.UNKNOWN


def test_heartbeat_cannot_clear_configuring_pairing_state():
    assert heartbeat_worker_target_state(
        "configuring", 0, "healthy"
    ) == WorkerState.CONFIGURING


def test_heartbeat_cannot_clear_needs_attention_pairing_state():
    assert heartbeat_worker_target_state(
        "needs_attention", 0, "healthy"
    ) == WorkerState.NEEDS_ATTENTION
