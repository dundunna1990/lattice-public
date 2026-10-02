import json

import pytest

from lattice.ip_change.setup import StaticIPPlan
from lattice.ip_change import worker_assignment


def _signed_payload(address="10.77.0.201"):
    return {
        "assignment_id": "11111111-1111-4111-8111-111111111111",
        "worker_hostname": "worker-node",
        "worker_node_id": "22222222-2222-4222-8222-222222222222",
        "issued_at": "2026-09-01T00:00:00+00:00",
        "address": address,
        "prefix": 24,
        "gateway": "10.77.0.1",
        "dns": ["10.77.0.1"],
        "signature": "-----BEGIN SSH SIGNATURE-----\ntest\n-----END SSH SIGNATURE-----\n",
    }


def test_worker_queues_only_a_master_signed_exact_assignment(monkeypatch, tmp_path):
    request_path = tmp_path / "network-assignment-request.json"
    monkeypatch.setattr(worker_assignment, "REQUEST_PATH", request_path)
    monkeypatch.setattr(worker_assignment, "normalize_assignment", lambda payload: payload)

    worker_assignment.queue_network_assignment(_signed_payload())

    queued = json.loads(request_path.read_text())
    assert queued["address"] == "10.77.0.201"
    assert queued["assignment_id"] == "11111111-1111-4111-8111-111111111111"
    assert "BEGIN SSH SIGNATURE" in queued["signature"]


def test_queue_refuses_unsigned_assignment(monkeypatch, tmp_path):
    request_path = tmp_path / "network-assignment-request.json"
    monkeypatch.setattr(worker_assignment, "REQUEST_PATH", request_path)
    monkeypatch.setattr(worker_assignment, "normalize_assignment", lambda payload: payload)
    payload = _signed_payload()
    payload.pop("signature")
    with pytest.raises(worker_assignment.StaticIPError, match="did not sign"):
        worker_assignment.queue_network_assignment(payload)
    assert not request_path.exists()


def test_root_authorization_is_burned_before_network_apply(monkeypatch, tmp_path):
    request_path = tmp_path / "network-assignment-request.json"
    request_path.write_text("{}")
    request_path.chmod(0o600)
    payload = _signed_payload()
    order = []
    plans = []
    monkeypatch.setattr(worker_assignment, "REQUEST_PATH", request_path)
    monkeypatch.setattr(worker_assignment, "NETWORK_POLICY_PATH", tmp_path / "network-policy.json")
    monkeypatch.setattr(worker_assignment, "_read_assignment_request", lambda _: payload)
    monkeypatch.setattr(
        worker_assignment, "_verify_and_consume_authorization",
        lambda p: (order.append("consume") or {k: v for k, v in p.items() if k != "signature"}),
    )
    monkeypatch.setattr(worker_assignment, "_default_interface", lambda: "enp3s0")
    monkeypatch.setattr(worker_assignment, "detect_connection", lambda _: "Wired connection 1")
    monkeypatch.setattr(worker_assignment, "apply_static_ip", lambda plan: (order.append("apply"), plans.append(plan)))
    monkeypatch.setattr(worker_assignment, "_arm_network_reconciliation", lambda: None)

    plan = worker_assignment.run_assignment(request_path)

    assert plan == StaticIPPlan("enp3s0", "Wired connection 1", "10.77.0.201", 24, "10.77.0.1", ("10.77.0.1",))
    assert plans == [plan]
    assert order == ["consume", "apply"]
    assert not request_path.exists()


def test_successful_canonical_assignment_replaces_preassignment_policy_and_arms_reconcile(monkeypatch, tmp_path):
    request_path = tmp_path / "network-assignment-request.json"
    result_path = tmp_path / "network-assignment-result.json"
    policy_path = tmp_path / "network-policy.json"
    request_path.write_text("{}")
    policy_path.write_text('{"address":"10.77.0.85"}\n')
    payload = _signed_payload("10.77.0.202")
    payload["gateway"] = "10.77.0.254"
    payload["dns"] = ["10.77.0.254"]
    monkeypatch.setattr(worker_assignment, "REQUEST_PATH", request_path)
    monkeypatch.setattr(worker_assignment, "RESULT_PATH", result_path)
    monkeypatch.setattr(worker_assignment, "NETWORK_POLICY_PATH", policy_path)
    monkeypatch.setattr(worker_assignment, "_read_assignment_request", lambda _: payload)
    monkeypatch.setattr(worker_assignment, "_verify_and_consume_authorization", lambda p: {k: v for k, v in p.items() if k != "signature"})
    monkeypatch.setattr(worker_assignment, "_default_interface", lambda: "wlan0")
    monkeypatch.setattr(worker_assignment, "detect_connection", lambda _: "home")
    monkeypatch.setattr(worker_assignment, "validate_plan", lambda plan: plan)
    monkeypatch.setattr(worker_assignment, "apply_static_ip", lambda plan: None)
    armed = []
    monkeypatch.setattr(worker_assignment, "_arm_network_reconciliation", lambda: armed.append(True))

    plan = worker_assignment.run_assignment(request_path)

    assert plan.address == "10.77.0.202"
    assert not policy_path.exists()
    assert json.loads(result_path.read_text()) == {"address": "10.77.0.202", "status": "complete"}
    assert armed == [True]
    assert not request_path.exists()


def test_arm_network_reconciliation_restarts_even_if_timer_is_already_enabled():
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    worker_assignment._arm_network_reconciliation(runner=runner)

    assert calls == [
        ["systemctl", "enable", worker_assignment.NETWORK_RECONCILE_TIMER],
        ["systemctl", "restart", worker_assignment.NETWORK_RECONCILE_TIMER],
    ]


def test_failed_assignment_never_arms_permanent_reconciliation(monkeypatch, tmp_path):
    request_path = tmp_path / "network-assignment-request.json"
    request_path.write_text("{}")
    payload = _signed_payload("10.77.0.202")
    payload["gateway"] = "10.77.0.254"
    payload["dns"] = []
    monkeypatch.setattr(worker_assignment, "_read_assignment_request", lambda _: payload)
    monkeypatch.setattr(worker_assignment, "_default_interface", lambda: "wlan0")
    monkeypatch.setattr(worker_assignment, "detect_connection", lambda _: "home")
    monkeypatch.setattr(worker_assignment, "validate_plan", lambda plan: plan)
    monkeypatch.setattr(worker_assignment, "apply_static_ip", lambda plan: (_ for _ in ()).throw(RuntimeError("apply failed")))
    armed = []
    monkeypatch.setattr(worker_assignment, "_arm_network_reconciliation", lambda: armed.append(True))

    with pytest.raises(RuntimeError, match="apply failed"):
        worker_assignment.run_assignment(request_path)
    assert armed == []
