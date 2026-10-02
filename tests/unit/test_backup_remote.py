from types import SimpleNamespace

import pytest

from lattice.backup import remote


def test_target_routes_rejects_local_self_addresses(monkeypatch):
    monkeypatch.setattr(
        remote,
        "load_mount_plans",
        lambda: [
            SimpleNamespace(
                node_id="target-node",
                ip="10.77.0.202",
                routes=("10.77.0.85", "172.17.0.1"),
            )
        ],
    )
    monkeypatch.setattr(remote, "selected_ip", lambda _node_id: "172.17.0.1")
    monkeypatch.setattr(
        remote,
        "remembered_routes",
        lambda _node_id: ["10.77.0.202", "172.17.0.1"],
    )

    routes = remote.target_routes(
        "target-node",
        local_address_resolver=lambda: {"10.77.0.200", "172.17.0.1"},
    )

    assert routes == ["10.77.0.202", "10.77.0.85"]


def test_target_routes_fails_if_only_candidates_are_local(monkeypatch):
    monkeypatch.setattr(
        remote,
        "load_mount_plans",
        lambda: [
            SimpleNamespace(
                node_id="target-node",
                ip="172.17.0.1",
                routes=(),
            )
        ],
    )
    monkeypatch.setattr(remote, "selected_ip", lambda _node_id: None)
    monkeypatch.setattr(remote, "remembered_routes", lambda _node_id: [])

    with pytest.raises(remote.RemoteBackupError, match="No current private-LAN route"):
        remote.target_routes(
            "target-node",
            local_address_resolver=lambda: {"172.17.0.1"},
        )


def test_sftp_capacity_uses_repo_filesystem_and_parses_kib():
    connection = remote.RemoteConnection(
        host="10.77.0.202",
        repository="sftp:lattice-bkp-test@10.77.0.202:repo",
        ssh_args=("-p", "22024", "-i", "/tmp/key", "-o", "BatchMode=yes"),
    )
    seen = {}

    def fake_runner(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "sftp> df repo\n"
                "        Size         Used        Avail       (root)    %Capacity\n"
                "   955691356    253067012    654004160    702624344          26%\n"
                "sftp> quit\n"
            ),
            stderr="",
        )

    total, free = remote.sftp_capacity(connection, runner=fake_runner)

    assert total == 955691356 * 1024
    assert free == 654004160 * 1024
    assert seen["command"][:4] == ["/usr/bin/sftp", "-q", "-b", "-"]
    assert "-P" in seen["command"]
    assert seen["kwargs"]["input"] == "df repo\nquit\n"


def test_sftp_capacity_rejects_invalid_response():
    connection = remote.RemoteConnection(
        host="10.77.0.202",
        repository="sftp:user@10.77.0.202:repo",
        ssh_args=("-p", "22024"),
    )
    with pytest.raises(remote.RemoteBackupError, match="capacity response is invalid"):
        remote.sftp_capacity(
            connection,
            runner=lambda *args, **kwargs: SimpleNamespace(
                returncode=0, stdout="unexpected", stderr=""
            ),
        )
