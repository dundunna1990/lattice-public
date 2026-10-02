from types import SimpleNamespace

import pytest

from lattice import operator_interface
from lattice.cli.commands import status as status_cmd


def test_operator_interface_rejects_write_commands():
    with pytest.raises(operator_interface.OperatorRequestError, match="not allowed"):
        operator_interface.execute_operator_request({
            "command": "alerts.ack",
            "params": {"alert_id": 1},
        })


def test_operator_interface_rejects_unknown_parameters():
    with pytest.raises(operator_interface.OperatorRequestError, match="unsupported"):
        operator_interface.execute_operator_request({
            "command": "status",
            "params": {"sql": "SELECT * FROM config"},
        })


def test_non_root_status_uses_operator_socket(monkeypatch, capsys):
    monkeypatch.setattr(status_cmd.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        "lattice.operator_client.request",
        lambda command, params=None: {
            "master_hostname": "master-one",
            "master_ip": "10.77.0.200",
            "workers": [{
                "hostname": "worker-one",
                "status": "healthy",
                "last_seen": "now",
            }],
            "alerts": [],
        },
    )
    assert status_cmd.cmd_status(SimpleNamespace()) is None
    output = capsys.readouterr().out
    assert "master-one" in output
    assert "worker-one" in output


def test_operator_interface_exposes_read_only_autoheal_status(monkeypatch):
    class Conn:
        def execute(self, *_args, **_kwargs):
            return self
        def fetchall(self):
            return [(1, "worker-one")]
        def close(self):
            pass
    monkeypatch.setattr(operator_interface, "get_db_connection", lambda: Conn())
    monkeypatch.setattr("lattice.core.config.get_config_value", lambda key: {
        "autoheal.mode": "automatic",
        "autoheal.enabled.1": "true",
    }.get(key))
    result = operator_interface.execute_operator_request({"command": "autoheal.status", "params": {}})
    assert result["data"] == {
        "mode": "automatic",
        "workers": [{"id": 1, "hostname": "worker-one", "enabled": True}],
    }


def test_non_root_autoheal_status_uses_operator_socket(monkeypatch, capsys):
    from lattice.cli.commands import autoheal as autoheal_cmd
    monkeypatch.setattr(autoheal_cmd.os, "geteuid", lambda: 1000)
    monkeypatch.setattr("lattice.operator_client.request", lambda command: {
        "mode": "automatic",
        "workers": [{"id": 1, "hostname": "worker-one", "enabled": True}],
    })
    args = SimpleNamespace(autoheal_cmd="status", worker_id=None)
    assert autoheal_cmd.handle_autoheal(args) == 0
    output = capsys.readouterr().out
    assert "Mode: automatic" in output
    assert "worker-one (ID 1): enabled" in output
