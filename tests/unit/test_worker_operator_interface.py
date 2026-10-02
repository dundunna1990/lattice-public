from types import SimpleNamespace

import pytest

from lattice import worker_operator_interface as worker_op
from lattice.cli.commands import status as status_cmd


def test_worker_operator_rejects_fleet_commands():
    with pytest.raises(
        worker_op.WorkerOperatorRequestError,
        match="available on the Master",
    ):
        worker_op.execute_worker_operator_request({
            "command": "workers.list",
            "params": {},
        })


def test_worker_operator_rejects_parameters():
    with pytest.raises(
        worker_op.WorkerOperatorRequestError,
        match="do not accept parameters",
    ):
        worker_op.execute_worker_operator_request({
            "command": "status",
            "params": {"sql": "SELECT 1"},
        })


def test_worker_status_uses_local_operator_socket(monkeypatch, capsys):
    monkeypatch.setattr(
        "lattice.wizard.lifecycle.current_role",
        lambda: "worker",
    )
    monkeypatch.setattr(
        "lattice.operator_client.request",
        lambda command: {
            "role": "worker",
            "hostname": "worker-node",
            "node_id": "11111111-1111-4111-8111-111111111111",
            "master_hostname": "master-node",
            "master_ip": "10.77.0.200",
            "fleet_generation": 4,
            "file_transport_generation": 4,
            "shell_transport_generation": 4,
            "services": [{"name": "sshd", "status": "healthy"}],
            "mounts": [],
            "shell_connections": [],
        },
    )
    assert status_cmd.cmd_status(SimpleNamespace()) is None
    out = capsys.readouterr().out
    assert "Worker: worker-node" in out
    assert "Master: master-node (10.77.0.200)" in out
    assert "Services: sshd: healthy" in out


def test_master_only_cli_gate_refuses_worker(monkeypatch, capsys):
    from lattice.cli import main as cli_main
    monkeypatch.setattr(
        "lattice.operator_client.request",
        lambda command: {"role": "worker"},
    )
    assert cli_main._refuse_master_only_command_on_worker("workers") is True
    assert "Lattice Worker" in capsys.readouterr().out


def test_master_only_cli_gate_allows_master(monkeypatch):
    from lattice.cli import main as cli_main
    monkeypatch.setattr(
        "lattice.operator_client.request",
        lambda command: {"role": "master"},
    )
    assert cli_main._refuse_master_only_command_on_worker("workers") is False
    assert cli_main._refuse_master_only_command_on_worker("pairing") is False
