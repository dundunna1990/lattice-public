"""Real file and trusted-shell recovery tests."""
from __future__ import annotations

import time

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _operator(command: str):
    return run(["sg", "lattice-operator", "-c", f"/opt/lattice/venv/bin/lattice {command}"], timeout=15)


def _wait_contains(command: str, needle: str, timeout: int = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _operator(command)
        if result.returncode == 0 and needle in result.stdout:
            return
        time.sleep(1)
    pytest.fail(f"operator command {command!r} never contained {needle!r}")


def test_e2e_file_011_mount_manager_restart_recovers_mount():
    result = run(["sudo", "-n", "systemctl", "restart", "lattice-mount-manager.service"], timeout=30)
    assert result.returncode == 0, result.stderr
    _wait_contains("mounts list", f"{WORKER_HOST}")
    _wait_contains("mounts list", "mounted")


def test_e2e_shell_011_connection_manager_restart_recovers_shell():
    result = run([
        "sudo", "-n", "systemctl", "restart",
        "lattice-shell-connection-manager.service",
    ], timeout=30)
    assert result.returncode == 0, result.stderr
    _wait_contains("shell status", f"{WORKER_HOST}")
    _wait_contains("shell status", "connected")


def test_e2e_file_010_worker_file_service_restart_recovers():
    result = ssh(
        WORKER_HOST,
        "sudo -n systemctl restart lattice-file-sshd.service",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    active = ssh(WORKER_HOST, "systemctl is-active lattice-file-sshd.service")
    assert active.returncode == 0
    assert active.stdout.strip() == "active"
    _wait_contains("mounts list", "mounted")


def test_e2e_shell_010_worker_shell_service_restart_recovers():
    before = ssh(
        WORKER_HOST,
        "systemctl show -p MainPID --value lattice-shell-sshd.service",
        timeout=15,
    )
    assert before.returncode == 0, before.stderr
    before_pid = before.stdout.strip()
    assert before_pid and before_pid != "0"

    # Restarting the SSH daemon may intentionally tear down the very
    # connection carrying this command. Exit 255 is therefore acceptable
    # only if we subsequently prove that a new daemon came up.
    result = ssh(
        WORKER_HOST,
        "sudo -n systemctl restart lattice-shell-sshd.service",
        timeout=30,
    )
    assert result.returncode in {0, 255}, result.stderr

    deadline = time.monotonic() + 60
    observed = []
    while time.monotonic() < deadline:
        probe = ssh(
            WORKER_HOST,
            "systemctl is-active lattice-shell-sshd.service; "
            "systemctl show -p MainPID --value lattice-shell-sshd.service",
            timeout=10,
        )
        if probe.returncode == 0:
            lines = [line.strip() for line in probe.stdout.splitlines() if line.strip()]
            observed.append(lines)
            if (
                len(lines) >= 2
                and lines[0] == "active"
                and lines[1] != "0"
                and lines[1] != before_pid
            ):
                break
        time.sleep(1)
    else:
        pytest.fail(
            "Worker shell SSH service did not recover with a new daemon; "
            f"observed={observed[-10:]}"
        )

    _wait_contains("shell status", "connected")
