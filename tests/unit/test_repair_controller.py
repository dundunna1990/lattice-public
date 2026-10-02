from types import SimpleNamespace

from lattice.repair.controller import RepairCandidate, RepairController


def _status(*, daemon="running", worker="healthy", file_ok=True, shell_ok=True, network="healthy"):
    return SimpleNamespace(
        master_hostname="master-node",
        daemon_status=daemon,
        workers=[{"id": 7, "hostname": "worker-node", "status": worker}],
        health={
            "network": {"state": network, "label": "Stable"},
            "node_access": [
                {"hostname": "worker-node", "file_ok": file_ok, "file": "DOWN" if not file_ok else "CONNECTED",
                 "shell_ok": shell_ok, "shell": "DOWN" if not shell_ok else "CONNECTED"},
            ],
        },
    )


def test_healthy_fleet_has_no_recommended_repairs():
    assert RepairController().diagnose(_status()) == []


def test_diagnosis_maps_real_lattice_layers_to_bounded_repairs():
    items = RepairController().diagnose(_status(daemon="stopped", worker="down", file_ok=False, shell_ok=False, network="degraded"))
    assert {item.id for item in items} == {"restart_master", "restart_worker", "retry_mount", "reconcile_shell", "reconcile_network"}
    assert all("systemctl" not in item.action for item in items)


def test_worker_candidates_are_context_sensitive():
    items = RepairController().candidates_for(_status(worker="healthy", file_ok=False), "worker-node")
    assert [item.id for item in items] == ["retry_mount"]


class _Audit:
    def __init__(self):
        self.calls = []
    def log_entry(self, **kwargs):
        self.calls.append(kwargs)
        return True
    def read_entries(self, limit=20):
        return []


def test_unknown_action_is_refused_and_audited(monkeypatch):
    from lattice.repair import controller
    monkeypatch.setattr(controller, "log_event", lambda *_args, **_kwargs: 1)
    audit = _Audit()
    candidate = RepairCandidate("not_a_command", "Unknown", "node", None, "problem", "action")
    result = RepairController(audit=audit).execute(candidate)
    assert not result.success and not result.verified
    assert "not a supported" in result.error
    assert [call["result"] for call in audit.calls] == ["manual_attempted", "blocked"]


def test_shell_wake_requests_reconciliation_without_killing_connections():
    from lattice.shell_access import manager
    manager._WAKE = False
    manager._wake()
    assert manager._WAKE is True
