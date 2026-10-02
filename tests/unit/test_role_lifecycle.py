"""Tests for the one-master-or-worker service lifecycle."""

from pathlib import Path
import subprocess

import pytest

from lattice.wizard.lifecycle import (
    RoleLifecycleError,
    activate_role,
    current_role,
    role_service_commands,
)
from lattice.cli.commands import system


def _ok_runner():
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    return calls, runner


def test_master_plan_disables_every_competing_activation_source() -> None:
    commands = role_service_commands("master")

    assert commands[:16] == [
        ["systemctl", "disable", "--now", "lattice-master.service"],
        ["systemctl", "disable", "--now", "lattice-worker.service"],
        ["systemctl", "disable", "--now", "lattice-network-assignment.path"],
        ["systemctl", "disable", "--now", "lattice-network-reconcile.timer"],
        ["systemctl", "stop", "lattice-network-reconcile.service"],
        ["systemctl", "disable", "--now", "lattice-health-watchdog.timer"],
        ["systemctl", "disable", "--now", "lattice-backup.timer"],
        ["systemctl", "disable", "--now", "lattice-care.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-maintenance.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-alerts.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-observation-refresh.timer"],
        ["systemctl", "disable", "--now", "lattice-backup-assignment-reconcile.timer"],
        ["systemctl", "disable", "--now", "lattice-credential-revoke.path"],
        [
            "systemctl",
            "disable",
            "--now",
            "lattice-file-transport-reconcile.path",
        ],
        [
            "systemctl",
            "disable",
            "--now",
            "lattice-file-sshd.service",
        ],
        [
            "systemctl",
            "disable",
            "--now",
            "lattice-mount-manager.service",
        ],
    ]
    assert ["systemctl", "enable", "--now", "lattice-network-reconcile.timer"] in commands
    assert ["systemctl", "restart", "lattice-init.service"] in commands
    assert [
        "systemctl",
        "enable",
        "--now",
        "lattice-file-sshd.service",
    ] in commands
    assert [
        "systemctl",
        "enable",
        "--now",
        "lattice-file-transport-reconcile.path",
    ] in commands
    assert [
        "systemctl",
        "enable",
        "--now",
        "lattice-mount-manager.service",
    ] in commands
    assert [
        "systemctl",
        "enable",
        "--now",
        "lattice-master.service",
    ] in commands

    assert [
        "systemctl",
        "enable",
        "--now",
        "lattice-health-watchdog.timer",
    ] in commands
    assert ["systemctl", "enable", "--now", "lattice-backup.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-care.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-backup-maintenance.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-backup-alerts.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-backup-observation-refresh.timer"] in commands
    assert [
        "systemctl", "enable", "--now", "lattice-backup-assignment-reconcile.timer"
    ] in commands


def test_network_reconcile_timer_reschedules_independently_of_service_state() -> None:
    timer = Path("deploy/systemd/lattice-network-reconcile.timer").read_text()

    assert "OnCalendar=*-*-* *:*:00/20" in timer
    assert "OnUnitActiveSec=" not in timer
    assert "OnUnitInactiveSec=" not in timer


def test_worker_plan_never_enables_master_or_watchdog() -> None:
    commands = role_service_commands("worker")

    assert ["systemctl", "enable", "--now", "lattice-worker.service"] in commands
    assert ["systemctl", "enable", "--now", "lattice-backup.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-care.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-backup-maintenance.timer"] in commands
    assert ["systemctl", "enable", "--now", "lattice-network-assignment.path"] in commands
    assert ["systemctl", "enable", "--now", "lattice-network-reconcile.timer"] not in commands
    assert ["systemctl", "enable", "--now", "lattice-master.service"] not in commands
    assert ["systemctl", "enable", "--now", "lattice-health-watchdog.timer"] not in commands
    assert ["systemctl", "enable", "--now", "lattice-backup-alerts.timer"] not in commands
    assert ["systemctl", "enable", "--now", "lattice-backup-observation-refresh.timer"] not in commands
    assert [
        "systemctl", "enable", "--now", "lattice-backup-assignment-reconcile.timer"
    ] not in commands


def test_failed_role_switch_restores_previous_role(tmp_path: Path) -> None:
    role_path = tmp_path / "role"
    role_path.write_text("master\n")
    calls, ok_runner = _ok_runner()

    def runner(command, **kwargs):
        if command == ["systemctl", "restart", "lattice-init.service"]:
            return subprocess.CompletedProcess(command, 1, "", "init failed")
        return ok_runner(command, **kwargs)

    with pytest.raises(RoleLifecycleError, match="init failed"):
        activate_role("worker", runner=runner, role_path=role_path)

    assert current_role(role_path) == "master"
    assert ["systemctl", "disable", "--now", "lattice-master.service"] in calls


def test_successful_role_switch_persists_selected_role(tmp_path: Path) -> None:
    role_path = tmp_path / "role"
    calls, runner = _ok_runner()

    activate_role("worker", runner=runner, role_path=role_path)

    assert current_role(role_path) == "worker"
    assert calls[-1] == ["systemctl", "enable", "--now", "lattice-network-assignment.path"]


def test_wizard_starts_the_selected_role_before_discovery() -> None:
    wizard = Path("lattice/wizard/orchestration.py").read_text()

    assert wizard.index('("write_start", write_start_step)') < wizard.index(
        '("key_exchange", key_exchange_step)'
    )
    assert 'if not data.get("role_service_started"):' in wizard
    assert "wait_for_local_worker_api(port)" in wizard


def test_service_units_refuse_the_wrong_role_without_stopping_the_right_role() -> None:
    master_unit = Path("deploy/systemd/lattice-master.service").read_text()
    worker_unit = Path("deploy/systemd/lattice-worker.service").read_text()

    assert "ExecCondition=/usr/bin/grep -qx master /etc/lattice/role" in master_unit
    assert "ExecCondition=/usr/bin/grep -qx worker /etc/lattice/role" in worker_unit

    # Conflicts= is intentionally forbidden here. systemd processes unit
    # conflicts before ExecCondition, so starting the wrong role could stop
    # the correct daemon before the role guard gets a chance to reject it.
    assert "Conflicts=lattice-worker.service" not in master_unit
    assert "Conflicts=lattice-master.service" not in worker_unit


def test_legacy_manual_ssh_copy_onboarding_is_not_in_the_cli_command() -> None:
    worker_commands = Path("lattice/cli/commands/workers.py").read_text()

    assert "ssh-copy-id" not in worker_commands
    assert "discover_waiting_workers" in worker_commands


def test_system_all_means_the_one_configured_role(monkeypatch) -> None:
    monkeypatch.setattr(system, "current_role", lambda: "worker")

    assert system._resolve_targets("all") == ["lattice-worker"]
    with pytest.raises(RoleLifecycleError, match="refusing"):
        system._resolve_targets("master")


def test_failed_role_switch_restores_previous_service_state(
    tmp_path: Path,
) -> None:
    role_path = tmp_path / "role"
    role_path.write_text("master\n")

    calls = []

    enabled = {
        "lattice-master.service",
        "lattice-health-watchdog.timer",
    }
    active = {
        "lattice-master.service",
        "lattice-health-watchdog.timer",
    }

    def runner(command, **_kwargs):
        calls.append(command)

        if command[:2] == [
            "systemctl",
            "is-enabled",
        ]:
            unit = command[2]
            return subprocess.CompletedProcess(
                command,
                0 if unit in enabled else 1,
                "",
                "",
            )

        if command[:2] == [
            "systemctl",
            "is-active",
        ]:
            unit = command[2]
            return subprocess.CompletedProcess(
                command,
                0 if unit in active else 3,
                "",
                "",
            )

        if command == [
            "systemctl",
            "restart",
            "lattice-init.service",
        ]:
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "init failed",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )

    with pytest.raises(
        RoleLifecycleError,
        match="init failed",
    ):
        activate_role(
            "worker",
            runner=runner,
            role_path=role_path,
        )

    assert current_role(role_path) == "master"

    assert [
        "systemctl",
        "enable",
        "lattice-master.service",
    ] in calls

    assert [
        "systemctl",
        "start",
        "lattice-master.service",
    ] in calls

    assert [
        "systemctl",
        "enable",
        "lattice-health-watchdog.timer",
    ] in calls

    assert [
        "systemctl",
        "start",
        "lattice-health-watchdog.timer",
    ] in calls

    assert [
        "systemctl",
        "enable",
        "lattice-worker.service",
    ] not in calls


def test_mount_manager_is_enabled_for_both_roles():
    for role in (
        "master",
        "worker",
    ):
        commands = role_service_commands(
            role
        )

        assert [
            "systemctl",
            "enable",
            "--now",
            "lattice-mount-manager.service",
        ] in commands
