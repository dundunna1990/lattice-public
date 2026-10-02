"""Real reboot / boot-recovery chaos tests."""
from __future__ import annotations

import time

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _wait_ssh(timeout: int = 180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        probe = ssh(WORKER_HOST, "true", timeout=8)
        if probe.returncode == 0:
            return
        time.sleep(3)
    pytest.fail("Worker SSH did not return after reboot")


def _wait_healthy(timeout: int = 180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = run(["sg", "lattice-operator", "-c", f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
        if status.returncode == 0 and "Status: healthy" in status.stdout:
            return
        time.sleep(3)
    pytest.fail("Worker did not return healthy after reboot")

def test_e2e_chaos_003_worker_reboot_recovers_all_channels():
    before = ssh(WORKER_HOST, "cat /proc/sys/kernel/random/boot_id")
    assert before.returncode == 0
    ssh(WORKER_HOST, "sudo -n systemctl reboot", timeout=8)
    time.sleep(5)
    _wait_ssh()
    after = ssh(WORKER_HOST, "cat /proc/sys/kernel/random/boot_id")
    assert after.returncode == 0
    assert after.stdout.strip() != before.stdout.strip()
    _wait_healthy()

    mounts = run(["sg", "lattice-operator", "-c", "/opt/lattice/venv/bin/lattice mounts list"])
    shell = run(["sg", "lattice-operator", "-c", "/opt/lattice/venv/bin/lattice shell status"])
    assert mounts.returncode == 0 and any(
        line.startswith(WORKER_HOST) and "mounted" in line for line in mounts.stdout.splitlines()
    )
    assert shell.returncode == 0 and any(
        line.startswith(WORKER_HOST) and "connected" in line for line in shell.stdout.splitlines()
    )
