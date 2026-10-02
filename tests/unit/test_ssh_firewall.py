"""Tests for first-time-only, narrow SSH firewall preparation."""

import subprocess
from types import SimpleNamespace

import pytest

from lattice.core.ssh_firewall import (
    SSHFirewallError,
    SSHFirewallResult,
    ensure_local_lan_ssh_firewall,
)


def _result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_active_ufw_gets_only_local_lan_ssh_and_role_api_rules():
    calls = []
    status_calls = 0

    def runner(command):
        nonlocal status_calls
        calls.append(command)
        if command == ["ufw", "status"]:
            status_calls += 1
            if status_calls == 1:
                return _result(stdout="Status: active\n")
            return _result(
                stdout=(
                    "Status: active\n"
                    "22/tcp ALLOW IN 10.77.0.0/24\n"
                    "22022/tcp ALLOW IN 10.77.0.0/24\n"
                    "22023/tcp ALLOW IN 10.77.0.0/24\n"
                    "22024/tcp ALLOW IN 10.77.0.0/24\n"
                    "9999/tcp ALLOW IN 10.77.0.0/24\n"
                )
            )
        if command[:2] == ["ufw", "allow"]:
            return _result(stdout="Rule added\n")
        raise AssertionError(f"Unexpected command: {command}")

    result = ensure_local_lan_ssh_firewall(
        api_port=9999,
        runner=runner,
        finder=lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
        subnet_detector=lambda: "10.77.0.0/24",
        require_root=False,
    )

    assert result.firewall == "ufw"
    assert result.changed is True
    assert ["ufw", "allow", "from", "10.77.0.0/24", "to", "any", "port", "22", "proto", "tcp", "comment", "Lattice local LAN"] in calls
    for port in (22, 22022, 22023, 22024, 9999):
        assert ["ufw", "allow", "from", "10.77.0.0/24", "to", "any", "port", str(port), "proto", "tcp", "comment", "Lattice local LAN"] in calls
    assert not any("enable" in command or "disable" in command for command in calls)


def test_inactive_ufw_is_never_enabled_or_changed():
    calls = []

    def runner(command):
        calls.append(command)
        return _result(stdout="Status: inactive\n")

    result = ensure_local_lan_ssh_firewall(
        api_port=8080,
        runner=runner,
        finder=lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
        subnet_detector=lambda: "10.77.0.0/24",
        require_root=False,
    )

    assert result.firewall == "ufw (inactive)"
    assert result.changed is False
    assert calls == [["ufw", "status"]]


def test_active_unsupported_firewall_stops_setup_without_disabling_it():
    calls = []

    def runner(command):
        calls.append(command)
        if command == ["nft", "list", "ruleset"]:
            return _result(stdout="table inet filter { chain input { type filter hook input priority 0; } }\n")
        raise AssertionError(f"Unexpected command: {command}")

    with pytest.raises(SSHFirewallError, match="will not guess or disable"):
        ensure_local_lan_ssh_firewall(
            api_port=8080,
            runner=runner,
            finder=lambda name: "/usr/sbin/nft" if name == "nft" else None,
            subnet_detector=lambda: "10.77.0.0/24",
            require_root=False,
        )

    assert calls == [["nft", "list", "ruleset"]]


def test_active_firewalld_gets_only_local_lan_ssh_and_role_api_rules():
    calls = []
    subnet = "10.20.30.0/24"
    rules = [
        f'rule family="ipv4" source address="{subnet}" port port="{port}" protocol="tcp" accept'
        for port in (22, 22022, 22023, 22024, 8080)
    ]

    def runner(command):
        calls.append(command)
        if command == ["firewall-cmd", "--state"]:
            return _result(stdout="running\n")
        if command == ["firewall-cmd", "--get-active-zones"]:
            return _result(stdout="public\n  interfaces: enp3s0\n")
        if "--add-rich-rule" in command:
            return _result(stdout="success\n")
        if command == ["firewall-cmd", "--zone", "public", "--list-rich-rules"]:
            return _result(stdout="\n".join(rules) + "\n")
        raise AssertionError(f"Unexpected command: {command}")

    result = ensure_local_lan_ssh_firewall(
        api_port=8080,
        runner=runner,
        finder=lambda name: "/usr/bin/firewall-cmd" if name == "firewall-cmd" else None,
        subnet_detector=lambda: subnet,
        require_root=False,
    )

    assert result.firewall == "firewalld"
    assert result.changed is True
    for rule in rules:
        assert ["firewall-cmd", "--permanent", "--zone", "public", "--add-rich-rule", rule] in calls
        assert ["firewall-cmd", "--zone", "public", "--add-rich-rule", rule] in calls
    assert not any("--add-service" in command for command in calls)
    assert not any("--add-port" in command for command in calls)
    assert not any("--reload" in command for command in calls)


def test_invalid_api_port_fails_before_inspecting_or_changing_firewall():
    calls = []

    with pytest.raises(SSHFirewallError, match="role API port"):
        ensure_local_lan_ssh_firewall(
            api_port=0,
            runner=lambda command: calls.append(command),
            finder=lambda name: "/usr/sbin/ufw",
            subnet_detector=lambda: "10.77.0.0/24",
            require_root=False,
        )

    assert calls == []


def test_ufw_rolls_back_new_ssh_rule_if_api_rule_fails():
    calls = []

    def runner(command):
        calls.append(command)
        if command == ["ufw", "status"]:
            return _result(stdout="Status: active\n")
        if command[:2] == ["ufw", "allow"]:
            port = command[command.index("port") + 1]
            if port == "8080":
                return _result(returncode=1, stderr="failed\n")
            return _result(stdout="Rule added\n")
        if command[:4] == ["ufw", "--force", "delete", "allow"]:
            return _result(stdout="Rule deleted\n")
        raise AssertionError(f"Unexpected command: {command}")

    with pytest.raises(SSHFirewallError, match="TCP/8080"):
        ensure_local_lan_ssh_firewall(
            api_port=8080, runner=runner,
            finder=lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
            subnet_detector=lambda: "10.77.0.0/24", require_root=False,
        )

    deleted_ports = [
        call[call.index("port") + 1]
        for call in calls
        if call[:4] == ["ufw", "--force", "delete", "allow"]
    ]
    assert deleted_ports == ["22024", "22023", "22022", "22"]


@pytest.mark.parametrize(
    ("data", "expected_port"),
    [
        ({"role": "master", "api_port": 8443}, 8443),
        ({"role": "worker"}, 9999),
    ],
)
def test_wizard_passes_selected_role_api_port(monkeypatch, data, expected_port):
    from lattice.wizard import orchestration

    selected_ports = []
    screen = SimpleNamespace(refresh=lambda: None, getch=lambda: None)
    monkeypatch.setattr(
        orchestration,
        "prepare_local_ssh",
        lambda: SimpleNamespace(service_name="ssh", backup_path=None),
    )
    monkeypatch.setattr(orchestration, "center_text", lambda *args: None)
    monkeypatch.setattr(orchestration.curses, "napms", lambda milliseconds: None)

    def configure_firewall(*, api_port):
        selected_ports.append(api_port)
        return SSHFirewallResult("ufw", "10.77.0.0/24", True)

    monkeypatch.setattr(
        orchestration,
        "ensure_local_lan_ssh_firewall",
        configure_firewall,
    )

    assert orchestration.ssh_firewall_step(screen, data, ni=True) == {}
    assert selected_ports == [expected_port]


def test_wizard_noninteractive_stops_when_no_supported_firewall_is_active(monkeypatch):
    from lattice.wizard import orchestration
    restored = []
    monkeypatch.setattr(orchestration, "restore_local_ssh", lambda result: restored.append(result.service_name))
    monkeypatch.setattr(orchestration, "remove_lattice_firewall_rules", lambda: False)

    screen = SimpleNamespace(refresh=lambda: None, getch=lambda: ord("y"))
    monkeypatch.setattr(orchestration, "prepare_local_ssh", lambda: SimpleNamespace(service_name="ssh", backup_path=None))
    monkeypatch.setattr(orchestration, "center_text", lambda *args: None)
    monkeypatch.setattr(orchestration.curses, "napms", lambda milliseconds: None)
    monkeypatch.setattr(
        orchestration,
        "ensure_local_lan_ssh_firewall",
        lambda *, api_port: SSHFirewallResult("ufw (inactive)", "10.77.0.0/24", False),
    )

    assert orchestration.ssh_firewall_step(screen, {"role": "worker"}, ni=True) is False


def test_wizard_interactive_requires_explicit_yes_without_active_firewall(monkeypatch):
    from lattice.wizard import orchestration
    restored = []
    monkeypatch.setattr(orchestration, "restore_local_ssh", lambda result: restored.append(result.service_name))
    monkeypatch.setattr(orchestration, "remove_lattice_firewall_rules", lambda: False)

    answers = iter((ord("n"), ord("y")))
    screen = SimpleNamespace(erase=lambda: None, refresh=lambda: None, getch=lambda: next(answers))
    monkeypatch.setattr(orchestration, "prepare_local_ssh", lambda: SimpleNamespace(service_name="ssh", backup_path=None))
    monkeypatch.setattr(orchestration, "center_text", lambda *args: None)
    monkeypatch.setattr(orchestration.curses, "napms", lambda milliseconds: None)
    monkeypatch.setattr(
        orchestration,
        "ensure_local_lan_ssh_firewall",
        lambda *, api_port: SSHFirewallResult("no supported active firewall", "10.77.0.0/24", False),
    )

    assert orchestration.ssh_firewall_step(screen, {"role": "master"}, ni=False) is False
    assert orchestration.ssh_firewall_step(screen, {"role": "master"}, ni=False) == {}


def test_inactive_ufw_can_be_staged_enabled_and_verified_safely(tmp_path):
    from lattice.core.ssh_firewall import enable_inactive_ufw_for_lattice

    defaults = tmp_path / "ufw"
    defaults.write_text('DEFAULT_INPUT_POLICY="DROP"\n')
    calls = []
    status_calls = 0

    def runner(command):
        nonlocal status_calls
        calls.append(command)
        if command == ["ufw", "status"]:
            status_calls += 1
            if status_calls == 1:
                return _result(stdout="Status: inactive\n")
            return _result(stdout=(
                "Status: active\n"
                "22/tcp ALLOW IN 10.77.0.0/24\n"
                "22022/tcp ALLOW IN 10.77.0.0/24\n"
                "22023/tcp ALLOW IN 10.77.0.0/24\n"
                "22024/tcp ALLOW IN 10.77.0.0/24\n"
                "9999/tcp ALLOW IN 10.77.0.0/24\n"
            ))
        if command[:2] == ["ufw", "allow"]:
            return _result(stdout="Rule added\n")
        if command == ["ufw", "--force", "enable"]:
            return _result(stdout="Firewall is active\n")
        raise AssertionError(f"Unexpected command: {command}")

    result = enable_inactive_ufw_for_lattice(
        api_port=9999, runner=runner,
        finder=lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
        subnet_detector=lambda: "10.77.0.0/24", require_root=False,
        defaults_path=defaults,
    )

    assert result.firewall == "ufw"
    assert result.changed is True
    enable_index = calls.index(["ufw", "--force", "enable"])
    for port in (22, 22022, 22023, 22024, 9999):
        rule = ["ufw", "allow", "from", "10.77.0.0/24", "to", "any", "port", str(port), "proto", "tcp", "comment", "Lattice local LAN"]
        assert calls.index(rule) < enable_index


def test_inactive_ufw_refuses_unsafe_default_input_policy(tmp_path):
    from lattice.core.ssh_firewall import enable_inactive_ufw_for_lattice

    defaults = tmp_path / "ufw"
    defaults.write_text('DEFAULT_INPUT_POLICY="ACCEPT"\n')
    calls = []

    def runner(command):
        calls.append(command)
        return _result(stdout="Status: inactive\n")

    with pytest.raises(SSHFirewallError, match="DROP/REJECT"):
        enable_inactive_ufw_for_lattice(
            api_port=9999, runner=runner,
            finder=lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
            subnet_detector=lambda: "10.77.0.0/24", require_root=False,
            defaults_path=defaults,
        )
    assert calls == [["ufw", "status"]]


def test_inactive_ufw_rolls_back_staged_rules_if_enable_fails(tmp_path):
    from lattice.core.ssh_firewall import enable_inactive_ufw_for_lattice

    defaults = tmp_path / "ufw"
    defaults.write_text('DEFAULT_INPUT_POLICY="DROP"\n')
    calls = []

    def runner(command):
        calls.append(command)
        if command == ["ufw", "status"]:
            return _result(stdout="Status: inactive\n")
        if command[:2] == ["ufw", "allow"]:
            return _result(stdout="Rule added\n")
        if command == ["ufw", "--force", "enable"]:
            return _result(returncode=1, stderr="enable failed\n")
        if command[:4] == ["ufw", "--force", "delete", "allow"]:
            return _result(stdout="Rule deleted\n")
        raise AssertionError(f"Unexpected command: {command}")

    with pytest.raises(SSHFirewallError, match="Could not enable UFW"):
        enable_inactive_ufw_for_lattice(
            api_port=9999, runner=runner,
            finder=lambda name: "/usr/sbin/ufw" if name == "ufw" else None,
            subnet_detector=lambda: "10.77.0.0/24", require_root=False,
            defaults_path=defaults,
        )
    deleted_ports = [call[call.index("port") + 1] for call in calls if call[:4] == ["ufw", "--force", "delete", "allow"]]
    assert deleted_ports == ["9999", "22024", "22023", "22022", "22"]


def test_wizard_offers_safe_enable_for_inactive_ufw(monkeypatch):
    from lattice.wizard import orchestration

    answers = iter((ord("\n"),))
    screen = SimpleNamespace(erase=lambda: None, refresh=lambda: None, getch=lambda: next(answers))
    monkeypatch.setattr(orchestration, "prepare_local_ssh", lambda: SimpleNamespace(service_name="ssh", backup_path=None))
    monkeypatch.setattr(orchestration, "center_text", lambda *args: None)
    monkeypatch.setattr(orchestration.curses, "napms", lambda milliseconds: None)
    monkeypatch.setattr(orchestration, "ensure_local_lan_ssh_firewall", lambda *, api_port: SSHFirewallResult("ufw (inactive)", "10.77.0.0/24", False))
    enabled = []
    monkeypatch.setattr(orchestration, "enable_inactive_ufw_for_lattice", lambda *, api_port: enabled.append(api_port) or SSHFirewallResult("ufw", "10.77.0.0/24", True, (22, 22022, 22023, api_port)))

    assert orchestration.ssh_firewall_step(screen, {"role": "worker"}, ni=False) == {}
    assert enabled == [9999]


def test_wizard_declining_inactive_ufw_enable_stops_setup(monkeypatch):
    from lattice.wizard import orchestration
    restored = []
    monkeypatch.setattr(orchestration, "restore_local_ssh", lambda result: restored.append(result.service_name))
    monkeypatch.setattr(orchestration, "remove_lattice_firewall_rules", lambda: False)

    screen = SimpleNamespace(erase=lambda: None, refresh=lambda: None, getch=lambda: ord("n"))
    monkeypatch.setattr(orchestration, "prepare_local_ssh", lambda: SimpleNamespace(service_name="ssh", backup_path=None))
    monkeypatch.setattr(orchestration, "center_text", lambda *args: None)
    monkeypatch.setattr(orchestration.curses, "napms", lambda milliseconds: None)
    monkeypatch.setattr(orchestration, "ensure_local_lan_ssh_firewall", lambda *, api_port: SSHFirewallResult("ufw (inactive)", "10.77.0.0/24", False))

    assert orchestration.ssh_firewall_step(screen, {"role": "worker"}, ni=False) is False
