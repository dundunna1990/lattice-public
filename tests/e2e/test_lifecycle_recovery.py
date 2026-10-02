"""State-changing service lifecycle tests for the real two-machine lab."""
from __future__ import annotations

import time

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _ok(result, label: str) -> str:
    assert result.returncode == 0, (
        f"{label} failed\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return result.stdout.strip()


def _wait_worker_healthy(timeout: int = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["sg", "lattice-operator", "-c",
                      f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
        if result.returncode == 0 and "Status: healthy" in result.stdout:
            return
        time.sleep(1)
    pytest.fail(f"{WORKER_HOST} did not return healthy within {timeout}s")


def test_e2e_life_010_master_graceful_restart():
    before = run(["systemctl", "show", "-p", "MainPID", "lattice-master.service"])
    old_pid = _ok(before, "master PID")
    restarted = run([
        "sudo", "-n", "/opt/lattice/venv/bin/lattice",
        "system", "restart", "master",
    ], timeout=30)
    _ok(restarted, "master restart")
    active = run(["systemctl", "is-active", "lattice-master.service"])
    assert _ok(active, "master service after restart") == "active"
    after = run(["systemctl", "show", "-p", "MainPID", "lattice-master.service"])
    assert _ok(after, "new master PID") != old_pid
    journal = run(["journalctl", "-u", "lattice-master.service", "-n", "30", "--no-pager"])
    text = _ok(journal, "master journal")
    assert "Deactivated successfully" in text
    assert "killing process" not in text.lower()
    _wait_worker_healthy()


def test_e2e_life_011_worker_restart_and_recovery():
    restarted = ssh(WORKER_HOST, "sudo -n /opt/lattice/venv/bin/lattice system restart worker", timeout=30)
    _ok(restarted, "worker restart")
    active = ssh(WORKER_HOST, "systemctl is-active lattice-worker.service")
    assert _ok(active, "worker service after restart") == "active"
    _wait_worker_healthy()
