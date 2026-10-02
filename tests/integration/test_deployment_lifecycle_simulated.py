"""Safe deployment lifecycle simulation.

No real systemd, package manager, filesystem integration, or Lattice daemon
is touched. A fake systemd runner exercises the production role-transition
code and verifies state after success and injected failure.
"""

from pathlib import Path
import subprocess

import pytest

from lattice.wizard.lifecycle import (
    RoleLifecycleError,
    activate_role,
    current_role,
)


class FakeSystemd:
    def __init__(
        self,
        *,
        enabled=(),
        active=(),
    ):
        self.enabled = set(enabled)
        self.active = set(active)
        self.calls = []
        self.fail_command = None

    def runner(
        self,
        command,
        **_kwargs,
    ):
        self.calls.append(
            list(command)
        )

        if (
            self.fail_command is not None
            and command == self.fail_command
        ):
            return subprocess.CompletedProcess(
                command,
                1,
                "",
                "injected deployment failure",
            )

        if command[0] != "systemctl":
            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        action = command[1]

        if action == "is-enabled":
            unit = command[2]
            return subprocess.CompletedProcess(
                command,
                0 if unit in self.enabled else 1,
                "",
                "",
            )

        if action == "is-active":
            unit = command[2]
            return subprocess.CompletedProcess(
                command,
                0 if unit in self.active else 3,
                "",
                "",
            )

        if action == "disable":
            if command[2] == "--now":
                unit = command[3]
                self.enabled.discard(unit)
                self.active.discard(unit)
            else:
                unit = command[2]
                self.enabled.discard(unit)

            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        if action == "enable":
            if command[2] == "--now":
                unit = command[3]
                self.enabled.add(unit)
                self.active.add(unit)
            else:
                unit = command[2]
                self.enabled.add(unit)

            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        if action == "start":
            self.active.add(
                command[2]
            )
            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        if action == "restart":
            self.active.add(
                command[2]
            )
            return subprocess.CompletedProcess(
                command,
                0,
                "",
                "",
            )

        return subprocess.CompletedProcess(
            command,
            0,
            "",
            "",
        )


def test_simulated_master_to_worker_deployment_transition(
    tmp_path: Path,
):
    role_path = tmp_path / "role"
    role_path.write_text(
        "master\n"
    )

    systemd = FakeSystemd(
        enabled={
            "lattice-master.service",
            "lattice-health-watchdog.timer",
        },
        active={
            "lattice-master.service",
            "lattice-health-watchdog.timer",
        },
    )

    activate_role(
        "worker",
        runner=systemd.runner,
        role_path=role_path,
    )

    assert current_role(
        role_path
    ) == "worker"

    assert (
        "lattice-master.service"
        not in systemd.active
    )

    assert (
        "lattice-health-watchdog.timer"
        not in systemd.active
    )

    assert (
        "lattice-worker.service"
        in systemd.active
    )

    assert (
        "lattice-worker.service"
        in systemd.enabled
    )

    assert (
        "lattice-network-assignment.path"
        in systemd.enabled
    )

    assert (
        "lattice-credential-revoke.path"
        in systemd.enabled
    )


def test_simulated_failed_switch_restores_complete_worker_state(
    tmp_path: Path,
):
    role_path = tmp_path / "role"
    role_path.write_text(
        "worker\n"
    )

    worker_units = {
        "lattice-worker.service",
        "lattice-network-assignment.path",
        "lattice-credential-revoke.path",
    }

    systemd = FakeSystemd(
        enabled=worker_units,
        active=worker_units,
    )

    systemd.fail_command = [
        "systemctl",
        "restart",
        "lattice-init.service",
    ]

    with pytest.raises(
        RoleLifecycleError,
        match="injected deployment failure",
    ):
        activate_role(
            "master",
            runner=systemd.runner,
            role_path=role_path,
        )

    # Role identity is restored first.
    assert current_role(
        role_path
    ) == "worker"

    # Exact old worker activation sources are restored.
    for unit in worker_units:
        assert unit in systemd.enabled
        assert unit in systemd.active

    # Failed master activation does not survive rollback.
    assert (
        "lattice-master.service"
        not in systemd.enabled
    )
    assert (
        "lattice-master.service"
        not in systemd.active
    )
    assert (
        "lattice-health-watchdog.timer"
        not in systemd.enabled
    )
    assert (
        "lattice-health-watchdog.timer"
        not in systemd.active
    )
