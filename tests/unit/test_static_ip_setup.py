"""Static-IP safety tests; every operating-system command is simulated."""

import json
from pathlib import Path
import stat
import subprocess

import pytest

from lattice.ip_change.boot_recovery import boot_recovery
from lattice.ip_change.monitor import check_ip_drift_once
from lattice.ip_change.setup import (
    StaticIPError,
    StaticIPPlan,
    apply_static_ip,
    detect_connection,
    detect_dns_servers,
    prefix_from_netmask,
    validate_plan,
)
from lattice.ip_change.state import read_state, write_state


def _result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _paths(monkeypatch, tmp_path):
    state_path = tmp_path / "ipchange.state"
    expected_path = tmp_path / "network.json"
    monkeypatch.setenv("LATTICE_IP_STATE_PATH", str(state_path))
    monkeypatch.setenv(
        "LATTICE_IP_ORIGINAL_STATE_PATH",
        str(tmp_path / "ipchange.original.json"),
    )
    monkeypatch.setenv("LATTICE_EXPECTED_NETWORK_PATH", str(expected_path))
    return state_path, expected_path


def _plan():
    return StaticIPPlan(
        interface="enp3s0",
        connection="Wired connection 1",
        address="192.168.50.20",
        prefix=24,
        gateway="192.168.50.1",
        dns=("192.168.50.1",),
    )


def _network_runner(calls, address_is_active=True):
    fields = {
        "ipv4.method": "auto\n",
        "ipv4.addresses": "192.168.50.8/24\n",
        "ipv4.gateway": "192.168.50.1\n",
        "ipv4.dns": "1.1.1.1\n",
    }

    def runner(command, **kwargs):
        calls.append(command)
        if command[0] == "ping":
            return _result()
        if command[0] == "arping":
            return _result(returncode=1)
        if command[:2] == ["nmcli", "-g"]:
            return _result(stdout=fields[command[2]])
        if command[0] == "ip":
            address = "192.168.50.20/24" if address_is_active else "192.168.50.8/24"
            return _result(stdout=f"2: enp3s0 inet {address} brd 192.168.50.255\n")
        return _result()

    return runner


def test_plan_validation_and_prefix_conversion():
    assert prefix_from_netmask("255.255.255.0") == 24

    with pytest.raises(StaticIPError, match="gateway is not inside"):
        validate_plan(
            StaticIPPlan("eth0", "wired", "10.77.0.10", 24, "10.0.0.1")
        )
    with pytest.raises(StaticIPError, match="reserved"):
        validate_plan(
            StaticIPPlan("eth0", "wired", "10.77.0.0", 24, "10.77.0.1")
        )


def test_detect_connection_uses_active_profile_not_interface_name():
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return _result(stdout="Wired connection 1\n")

    assert detect_connection("enp3s0", runner) == "Wired connection 1"
    assert calls == [["nmcli", "-g", "GENERAL.CONNECTION", "device", "show", "enp3s0"]]


def test_success_saves_snapshot_verifies_and_persists_expected_network(monkeypatch, tmp_path):
    state_path, expected_path = _paths(monkeypatch, tmp_path)
    calls = []

    result = apply_static_ip(
        _plan(),
        runner=_network_runner(calls),
        require_root=False,
    )

    assert result["address"] == "192.168.50.20"
    assert json.loads(state_path.read_text())["status"] == "committed"
    expected = json.loads(expected_path.read_text())
    assert expected["interface"] == "enp3s0"
    assert expected["connection"] == "Wired connection 1"
    assert stat.S_IMODE(expected_path.stat().st_mode) == 0o644
    assert [
        "nmcli", "connection", "up", "Wired connection 1", "ifname", "enp3s0"
    ] in calls


def test_failed_verification_restores_exact_old_profile(monkeypatch, tmp_path):
    _, expected_path = _paths(monkeypatch, tmp_path)
    calls = []

    with pytest.raises(StaticIPError, match="did not become active"):
        apply_static_ip(
            _plan(),
            runner=_network_runner(calls, address_is_active=False),
            require_root=False,
        )

    assert read_state()["status"] == "reverted"
    restore = [
        "nmcli", "connection", "modify", "Wired connection 1",
        "ipv4.method", "auto",
        "ipv4.addresses", "192.168.50.8/24",
        "ipv4.gateway", "192.168.50.1",
        "ipv4.dns", "1.1.1.1",
    ]
    assert restore in calls
    assert not expected_path.exists()


def test_address_conflict_stops_before_network_manager_change(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command[0] == "arping":
            return _result(returncode=0)
        return _result()

    with pytest.raises(StaticIPError, match="Another device"):
        apply_static_ip(_plan(), runner=runner, require_root=False)

    assert not any(command[:3] == ["nmcli", "connection", "modify"] for command in calls)


def test_boot_recovery_restores_an_interrupted_transaction(monkeypatch, tmp_path):
    _paths(monkeypatch, tmp_path)
    write_state(
        {
            "status": "applying",
            "interface": "enp3s0",
            "snapshot": {
                "connection": "Wired connection 1",
                "ipv4.method": "auto",
                "ipv4.addresses": "",
                "ipv4.gateway": "",
                "ipv4.dns": "",
            },
        }
    )
    calls = []

    assert boot_recovery(runner=_network_runner(calls)) is True
    assert read_state()["status"] == "recovered"
    assert any(command[:3] == ["nmcli", "connection", "modify"] for command in calls)


def test_runtime_monitor_reports_drift_without_running_nmcli(monkeypatch, tmp_path):
    _, expected_path = _paths(monkeypatch, tmp_path)
    expected_path.write_text(json.dumps({"interface": "enp3s0", "address": "192.168.50.20"}))
    expected_path.chmod(0o644)
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return _result(stdout="2: enp3s0 inet 192.168.50.99/24 scope global enp3s0\n")

    result = check_ip_drift_once(runner)

    assert result == {
        "status": "drift",
        "interface": "enp3s0",
        "expected": "192.168.50.20",
        "actual": "192.168.50.99",
    }
    assert all(command[0] == "ip" for command in calls)


def test_corrupt_boot_recovery_state_is_quarantined(
    monkeypatch,
    tmp_path,
):
    state_path, _ = _paths(
        monkeypatch,
        tmp_path,
    )

    state_path.write_text(
        "{broken json"
    )
    state_path.chmod(0o600)

    with pytest.raises(
        RuntimeError,
        match="state is corrupt",
    ):
        boot_recovery(
            runner=lambda *_args, **_kwargs: None
        )

    assert not state_path.exists()

    quarantined = list(
        tmp_path.glob(
            "ipchange.state.corrupt-*"
        )
    )

    assert len(quarantined) == 1
    assert (
        quarantined[0].read_text()
        == "{broken json"
    )


def test_habets_arping_exit_one_without_error_means_address_is_free():
    from lattice.ip_change.setup import is_address_available

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return _result(returncode=1)

    assert is_address_available("wlan0", "10.77.0.220", runner) is True
    assert calls[0][:5] == ["arping", "-q", "-0", "-i", "wlan0"]


def test_habets_arping_exit_zero_means_address_is_in_use():
    from lattice.ip_change.setup import is_address_available

    assert is_address_available(
        "wlan0", "10.77.0.254", lambda command, **kwargs: _result(returncode=0)
    ) is False


def test_arping_command_error_is_not_misreported_as_address_conflict():
    from lattice.ip_change.setup import is_address_available

    def runner(command, **kwargs):
        return _result(returncode=2, stderr="permission denied")

    with pytest.raises(StaticIPError, match="permission denied"):
        is_address_available("wlan0", "10.77.0.220", runner)


def test_iputils_arping_fallback_uses_dad_semantics():
    from lattice.ip_change.setup import is_address_available

    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if "-i" in command:
            return _result(returncode=2, stderr="usage: arping [-D] [-I device]")
        return _result(returncode=0)

    assert is_address_available("eth0", "10.77.0.220", runner) is True
    assert calls[1][:4] == ["arping", "-D", "-I", "eth0"]



def test_detect_dns_servers_preserves_actual_networkmanager_dns():
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        return _result(stdout="10.77.0.254\n1.1.1.1\n10.77.0.254\n")
    assert detect_dns_servers("wlan0", runner=runner) == ("10.77.0.254", "1.1.1.1")
    assert calls == [["nmcli", "-g", "IP4.DNS", "device", "show", "wlan0"]]


def test_detect_dns_servers_accepts_pipe_delimited_networkmanager_output():
    runner = lambda command, **kwargs: _result(stdout="10.77.0.254 | 203.0.113.53\n")
    assert detect_dns_servers("wlan0", runner=runner) == ("10.77.0.254", "203.0.113.53")


def test_detect_dns_servers_refuses_silent_empty_detection():
    with pytest.raises(StaticIPError, match="did not report"):
        detect_dns_servers("wlan0", runner=lambda command, **kwargs: _result(stdout="\n"))
