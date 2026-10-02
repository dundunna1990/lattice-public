import subprocess

import pytest

from lattice.ip_change import setup
from lattice.ip_change import uninstall_restore
from lattice.ip_change.state import (
    read_original_network_state,
    read_state,
)


def _result(command=None, **kwargs):
    return subprocess.CompletedProcess(
        command or [],
        0,
        stdout="",
        stderr="",
    )


def _paths(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "LATTICE_IP_STATE_PATH",
        str(tmp_path / "ipchange.state"),
    )
    monkeypatch.setenv(
        "LATTICE_IP_ORIGINAL_STATE_PATH",
        str(tmp_path / "ipchange.original.json"),
    )
    monkeypatch.setenv(
        "LATTICE_EXPECTED_NETWORK_PATH",
        str(tmp_path / "network.json"),
    )


def test_second_static_change_preserves_first_original_snapshot(
    monkeypatch,
    tmp_path,
):
    _paths(monkeypatch, tmp_path)

    original = {
        "connection": "Home WiFi",
        "ipv4.method": "auto",
        "ipv4.addresses": "",
        "ipv4.gateway": "",
        "ipv4.dns": "",
    }

    intermediate = {
        "connection": "Home WiFi",
        "ipv4.method": "manual",
        "ipv4.addresses": "10.77.0.201/24",
        "ipv4.gateway": "10.77.0.254",
        "ipv4.dns": "10.77.0.254",
    }

    snapshots = iter([original, intermediate])

    monkeypatch.setattr(
        setup,
        "snapshot_connection",
        lambda *_args, **_kwargs: dict(next(snapshots)),
    )
    monkeypatch.setattr(
        setup,
        "_gateway_is_reachable",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        setup,
        "_address_is_available",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(
        setup,
        "_address_is_present",
        lambda *_args, **_kwargs: True,
    )

    first = setup.StaticIPPlan(
        "wlan0",
        "Home WiFi",
        "10.77.0.201",
        24,
        "10.77.0.254",
        ("10.77.0.254",),
    )

    second = setup.StaticIPPlan(
        "wlan0",
        "Home WiFi",
        "10.77.0.203",
        24,
        "10.77.0.254",
        ("10.77.0.254",),
    )

    setup.apply_static_ip(
        first,
        runner=_result,
        require_root=False,
    )

    saved_original = read_original_network_state()

    assert saved_original == {
        "interface": "wlan0",
        "snapshot": original,
    }

    setup.apply_static_ip(
        second,
        runner=_result,
        require_root=False,
    )

    assert read_original_network_state() == saved_original

    transaction = read_state()
    assert transaction["snapshot"] == intermediate
    assert (
        transaction["previous_expected"]["address"]
        == "10.77.0.201"
    )


def test_uninstall_prefers_permanent_original_snapshot(
    monkeypatch,
):
    original = {
        "connection": "Home WiFi",
        "ipv4.method": "auto",
        "ipv4.addresses": "",
        "ipv4.gateway": "",
        "ipv4.dns": "",
    }

    monkeypatch.setattr(
        uninstall_restore,
        "read_original_network_state",
        lambda: {
            "interface": "wlan0",
            "snapshot": original,
        },
    )

    monkeypatch.setattr(
        uninstall_restore,
        "read_state",
        lambda: {
            "interface": "wlan0",
            "snapshot": {
                "connection": "Home WiFi",
                "ipv4.method": "manual",
                "ipv4.addresses": "10.77.0.201/24",
            },
            "previous_expected": {
                "address": "10.77.0.201",
            },
        },
    )

    restored = []

    monkeypatch.setattr(
        uninstall_restore,
        "restore_connection",
        lambda snapshot, interface: restored.append(
            (dict(snapshot), interface)
        ),
    )
    monkeypatch.setattr(
        uninstall_restore,
        "snapshot_connection",
        lambda _connection: dict(original),
    )

    uninstall_restore.restore_saved_network()

    assert restored == [(original, "wlan0")]


def test_uninstall_refuses_intermediate_snapshot_as_original(
    monkeypatch,
):
    monkeypatch.setattr(
        uninstall_restore,
        "read_original_network_state",
        lambda: None,
    )

    monkeypatch.setattr(
        uninstall_restore,
        "read_state",
        lambda: {
            "interface": "wlan0",
            "snapshot": {
                "connection": "Home WiFi",
                "ipv4.method": "manual",
                "ipv4.addresses": "10.77.0.201/24",
            },
            "previous_expected": {
                "address": "10.77.0.201",
            },
        },
    )

    with pytest.raises(
        setup.StaticIPError,
        match="original pre-Lattice",
    ):
        uninstall_restore.restore_saved_network()
