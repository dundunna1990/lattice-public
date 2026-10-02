import pytest

from lattice.ip_change import uninstall_restore
from lattice.ip_change.setup import StaticIPError


def _state():
    return {
        "interface": "wlan0",
        "snapshot": {
            "connection": "Home WiFi",
            "ipv4.method": "auto",
            "ipv4.addresses": "",
            "ipv4.gateway": "",
            "ipv4.dns": "",
        },
    }


def test_uninstall_network_restore_verifies_exact_saved_profile(monkeypatch):
    state = _state()
    calls = []

    monkeypatch.setattr(uninstall_restore, "read_state", lambda: state)
    monkeypatch.setattr(
        uninstall_restore,
        "read_original_network_state",
        lambda: None,
    )
    monkeypatch.setattr(
        uninstall_restore,
        "restore_connection",
        lambda snapshot, interface: calls.append((snapshot, interface)),
    )
    monkeypatch.setattr(
        uninstall_restore,
        "snapshot_connection",
        lambda connection: dict(state["snapshot"]),
    )

    uninstall_restore.restore_saved_network()

    assert calls == [(state["snapshot"], "wlan0")]


def test_uninstall_network_restore_refuses_false_success(monkeypatch):
    state = _state()

    monkeypatch.setattr(uninstall_restore, "read_state", lambda: state)
    monkeypatch.setattr(
        uninstall_restore,
        "read_original_network_state",
        lambda: None,
    )
    monkeypatch.setattr(
        uninstall_restore,
        "restore_connection",
        lambda snapshot, interface: None,
    )
    monkeypatch.setattr(
        uninstall_restore,
        "snapshot_connection",
        lambda connection: {
            "connection": connection,
            "ipv4.method": "manual",
            "ipv4.addresses": "10.77.0.200/24",
            "ipv4.gateway": "10.77.0.254",
            "ipv4.dns": "10.77.0.254",
        },
    )

    with pytest.raises(StaticIPError, match="restore verification failed"):
        uninstall_restore.restore_saved_network()
