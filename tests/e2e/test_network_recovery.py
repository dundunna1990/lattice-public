"""Network recovery/chaos tests for the designated Worker only."""
from __future__ import annotations

import time

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _worker_record_ip() -> str:
    result = run(["sg", "lattice-operator", "-c",
                  f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
    assert result.returncode == 0, result.stderr
    line = next(line for line in result.stdout.splitlines() if line.startswith("IP: "))
    return line.split(":", 1)[1].strip()


def _wait_healthy(timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["sg", "lattice-operator", "-c",
                      f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
        if result.returncode == 0 and "Status: healthy" in result.stdout:
            return
        time.sleep(2)
    pytest.fail("Worker did not recover to healthy after network disruption")


def test_e2e_chaos_001_networkmanager_restart_converges():
    expected_ip = _worker_record_ip()
    result = ssh(WORKER_HOST, "sudo -n systemctl restart NetworkManager.service", timeout=30)
    assert result.returncode == 0, result.stderr
    _wait_healthy()
    assert _worker_record_ip() == expected_ip


def test_e2e_net_001_reconcile_timer_and_policy_recover_after_restart():
    expected_ip = _worker_record_ip()
    timer = ssh(WORKER_HOST, "systemctl is-active lattice-network-reconcile.timer")
    assert timer.returncode == 0 and timer.stdout.strip() == "active"
    result = ssh(
        WORKER_HOST,
        "sudo -n systemctl start lattice-network-reconcile.service",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    _wait_healthy()
    assert _worker_record_ip() == expected_ip


def test_e2e_chaos_002_avahi_restart_preserves_membership():
    expected_ip = _worker_record_ip()
    result = ssh(WORKER_HOST, "sudo -n systemctl restart avahi-daemon.service", timeout=30)
    assert result.returncode == 0, result.stderr
    _wait_healthy()
    resolved = run(["getent", "hosts", f"{WORKER_HOST}.local"], timeout=15)
    assert resolved.returncode == 0
    assert resolved.stdout.split()[0] == expected_ip
