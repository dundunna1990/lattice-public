"""Safe tests for local SSH preparation; no real service is touched."""
from pathlib import Path
import subprocess

import pytest

from lattice.core.ssh_setup import SSHSetupError, prepare_local_ssh, restore_local_ssh


def _result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_prepare_local_ssh_backs_up_enables_and_verifies(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Port 22\n")
    calls = []
    active_checks = 0
    enabled_checks = 0

    def runner(command):
        nonlocal active_checks, enabled_checks
        calls.append(command)
        if command[:3] == ["systemctl", "show", "ssh"]:
            return _result(stdout="loaded\n")
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            active_checks += 1
            return _result(returncode=1 if active_checks == 1 else 0)
        if command[:3] == ["systemctl", "is-enabled", "--quiet"]:
            enabled_checks += 1
            return _result(returncode=1 if enabled_checks == 1 else 0)
        return _result()

    result = prepare_local_ssh(
        config_path=config,
        backup_dir=tmp_path / "backups",
        runner=runner,
        listening_check=lambda: True,
        require_root=False,
    )

    assert result.service_name == "ssh"
    assert result.active is True and result.enabled is True
    assert Path(result.backup_path).read_text() == "Port 22\n"
    assert ["systemctl", "enable", "--now", "ssh"] in calls


def test_prepare_local_ssh_rolls_service_state_back_after_failure(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Port 22\n")
    calls = []
    active_checks = 0
    enabled_checks = 0

    def runner(command):
        nonlocal active_checks, enabled_checks
        calls.append(command)
        if command[:3] == ["systemctl", "show", "ssh"]:
            return _result(stdout="loaded\n")
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            active_checks += 1
            return _result(returncode=1 if active_checks == 1 else 0)
        if command[:3] == ["systemctl", "is-enabled", "--quiet"]:
            enabled_checks += 1
            return _result(returncode=1 if enabled_checks == 1 else 0)
        return _result()

    with pytest.raises(SSHSetupError, match="not accepting"):
        prepare_local_ssh(
            config_path=config,
            backup_dir=tmp_path / "backups",
            runner=runner,
            listening_check=lambda: False,
            require_root=False,
        )

    assert ["systemctl", "stop", "ssh"] in calls
    assert ["systemctl", "disable", "ssh"] in calls
    assert config.read_text() == "Port 22\n"


def test_prepare_local_ssh_rejects_invalid_configuration_before_enabling(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("BadOption yes\n")
    calls = []

    def runner(command):
        calls.append(command)
        if command[:3] == ["systemctl", "show", "ssh"]:
            return _result(stdout="loaded\n")
        if command[:2] == ["systemctl", "is-active"] or command[:2] == ["systemctl", "is-enabled"]:
            return _result(returncode=0)
        if command[-1:] == ["-t"]:
            return _result(returncode=1, stderr="Bad configuration option")
        return _result()

    with pytest.raises(SSHSetupError, match="invalid"):
        prepare_local_ssh(
            config_path=config,
            backup_dir=tmp_path / "backups",
            runner=runner,
            listening_check=lambda: True,
            require_root=False,
        )

    assert ["systemctl", "enable", "--now", "ssh"] not in calls



def test_restore_local_ssh_uses_exact_backed_up_config_and_service_state(tmp_path):
    config = tmp_path / "sshd_config"
    config.write_text("Changed yes\n")
    backup = tmp_path / "sshd_config.before"
    backup.write_text("Port 22\n")
    calls = []
    def runner(command, **kwargs):
        calls.append(command)
        return _result()
    from lattice.core.ssh_setup import SSHSetupResult
    result = SSHSetupResult(
        service_name="ssh", backup_path=str(backup), active=True, enabled=True,
        was_active=False, was_enabled=False, config_path=str(config),
    )
    restore_local_ssh(result, runner=runner)
    assert config.read_text() == "Port 22\n"
    assert ["systemctl", "disable", "ssh"] in calls
    assert ["systemctl", "stop", "ssh"] in calls
