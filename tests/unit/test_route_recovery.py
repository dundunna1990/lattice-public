import os
import subprocess
from types import SimpleNamespace

from lattice.api.routes.heartbeat import (
    _seed_current_locators,
)
from lattice.core.lan_routes import (
    normalize_reported_routes,
)
import lattice.shell_access.manager as manager


def test_current_locator_outranks_history_without_deleting_it():
    node = "22222222-2222-4222-8222-222222222222"

    locators = _seed_current_locators(
        [(node, "10.77.0.203")]
    )

    locators[node].extend(
        [
            {
                "ip": "10.77.0.105",
                "interface": "wlo1",
                "kind": "wifi",
                "priority": 20,
            },
            {
                "ip": "10.77.0.201",
                "interface": "wlo1",
                "kind": "wifi",
                "priority": 20,
            },
        ]
    )

    routes = normalize_reported_routes(
        locators[node]
    )

    assert routes[0]["ip"] == "10.77.0.203"
    assert routes[0]["priority"] == 0

    assert {route["ip"] for route in routes} == {
        "10.77.0.105",
        "10.77.0.201",
        "10.77.0.203",
    }


def _prepare_manager(
    monkeypatch,
    tmp_path,
    *,
    fresh_alternate_rc,
):
    identity = SimpleNamespace(
        node_id="11111111-1111-4111-8111-111111111111",
        main_user="testuser",
    )

    monkeypatch.setattr(
        manager,
        "load_node_identity",
        lambda: identity,
    )
    monkeypatch.setattr(
        manager,
        "current_role",
        lambda: "master",
    )
    monkeypatch.setattr(
        manager,
        "ensure_rotation_staged_if_due",
        lambda: None,
    )
    monkeypatch.setattr(
        manager,
        "promote_local_rotation_if_requested",
        lambda: None,
    )
    monkeypatch.setattr(
        manager,
        "cleanup_completed_local_rotation",
        lambda: None,
    )

    monkeypatch.setattr(
        manager,
        "reconcile_shell_channel",
        lambda: {
            "enabled": True,
            "changed": False,
            "peer_plans": [
                {
                    "node_id": "22222222-2222-4222-8222-222222222222",
                    "hostname": "worker-one",
                    "ip": "10.77.0.203",
                    "remote_user": "workeruser",
                    "routes": [
                        {
                            "ip": "10.77.0.203",
                            "interface": "",
                            "kind": "unknown",
                            "priority": 0,
                        },
                        {
                            "ip": "10.77.0.201",
                            "interface": "wlo1",
                            "kind": "wifi",
                            "priority": 20,
                        },
                        {
                            "ip": "10.77.0.105",
                            "interface": "wlo1",
                            "kind": "wifi",
                            "priority": 20,
                        },
                    ],
                }
            ],
        },
    )

    monkeypatch.setattr(
        manager.pwd,
        "getpwnam",
        lambda _name: SimpleNamespace(
            pw_uid=os.getuid(),
            pw_gid=os.getgid(),
        ),
    )

    monkeypatch.setattr(
        manager,
        "CONTROL_ROOT",
        tmp_path / "control",
    )
    monkeypatch.setattr(
        manager.os,
        "chown",
        lambda *_args, **_kwargs: None,
    )

    monkeypatch.setattr(
        manager,
        "selected_ip",
        lambda _node: "10.77.0.201",
    )

    monkeypatch.setattr(
        manager,
        "remembered_routes",
        lambda _node: [
            "10.77.0.201",
            "10.77.0.105",
        ],
    )

    monkeypatch.setattr(
        manager,
        "discovered_hostname_ips",
        lambda _host: [],
    )

    monkeypatch.setattr(
        manager,
        "load_config",
        lambda: SimpleNamespace(
            shell_access=SimpleNamespace(
                port=22023
            )
        ),
    )

    connected = []

    monkeypatch.setattr(
        manager,
        "mark_connected",
        lambda node, host, ip: connected.append(
            (node, host, ip)
        ),
    )
    monkeypatch.setattr(
        manager,
        "mark_unavailable",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        manager,
        "mark_retired",
        lambda *_args, **_kwargs: None,
    )

    calls = []

    def fake_run(_uid, _gid, argv):
        calls.append(list(argv))

        if (
            "ControlMaster=no" in argv
            and "10.77.0.201" in " ".join(argv)
        ):
            return subprocess.CompletedProcess(
                argv,
                fresh_alternate_rc,
                stdout="",
                stderr="",
            )

        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        manager,
        "_run_as",
        fake_run,
    )

    return calls, connected


def test_dead_old_controlmaster_route_is_replaced(
    monkeypatch,
    tmp_path,
):
    calls, connected = _prepare_manager(
        monkeypatch,
        tmp_path,
        fresh_alternate_rc=255,
    )

    manager.reconcile_connections()

    assert any(
        "ControlMaster=no" in call
        and "workeruser@10.77.0.201" in call
        for call in calls
    )

    assert any(
        "-O" in call
        and "exit" in call
        for call in calls
    )

    assert any(
        "-fN" in call
        and "workeruser@10.77.0.203" in call
        for call in calls
    )

    assert connected == [
        (
            "22222222-2222-4222-8222-222222222222",
            "worker-one",
            "10.77.0.203",
        )
    ]


def test_live_alternate_route_is_preserved(
    monkeypatch,
    tmp_path,
):
    calls, connected = _prepare_manager(
        monkeypatch,
        tmp_path,
        fresh_alternate_rc=0,
    )

    manager.reconcile_connections()

    assert any(
        "ControlMaster=no" in call
        and "workeruser@10.77.0.201" in call
        for call in calls
    )

    assert not any(
        "-O" in call
        and "exit" in call
        for call in calls
    )

    assert not any(
        "-fN" in call
        for call in calls
    )

    assert connected == [
        (
            "22222222-2222-4222-8222-222222222222",
            "worker-one",
            "10.77.0.201",
        )
    ]
