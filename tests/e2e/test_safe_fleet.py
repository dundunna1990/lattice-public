"""Low-risk real-fleet smoke tests for master-node and worker-node."""
from __future__ import annotations

import socket

import pytest

from .conftest import MASTER_HOST, WORKER_HOST, run, ssh

pytestmark = pytest.mark.e2e


def _assert_ok(result, label: str) -> str:
    assert result.returncode == 0, (
        f"{label} failed\ncommand={result.command}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    return result.stdout.strip()


def test_e2e_life_001_runs_on_expected_master(e2e_hosts):
    master, worker = e2e_hosts
    assert socket.gethostname() == master
    assert worker == WORKER_HOST


def test_e2e_life_002_master_service_active():
    result = run(["systemctl", "is-active", "lattice-master.service"])
    assert _assert_ok(result, "master service") == "active"

def test_e2e_life_003_worker_service_active():
    result = ssh(WORKER_HOST, "systemctl is-active lattice-worker.service")
    assert _assert_ok(result, "worker service") == "active"


def test_e2e_life_004_master_sees_worker_healthy():
    result = run([
        "sg", "lattice-operator", "-c",
        f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}",
    ])
    output = _assert_ok(result, "operator worker status")
    assert f"Hostname: {WORKER_HOST}" in output
    assert "Status: healthy" in output


def test_e2e_file_001_worker_mount_is_mounted():
    result = run([
        "sg", "lattice-operator", "-c",
        "/opt/lattice/venv/bin/lattice mounts list",
    ])
    output = _assert_ok(result, "operator mount status")
    lines = [line for line in output.splitlines() if line.startswith(WORKER_HOST)]
    assert len(lines) == 1
    assert "mounted" in lines[0]


def test_e2e_shell_001_worker_shell_is_connected():
    result = run([
        "sg", "lattice-operator", "-c",
        "/opt/lattice/venv/bin/lattice shell status",
    ])
    output = _assert_ok(result, "operator shell status")
    lines = [line for line in output.splitlines() if line.startswith(WORKER_HOST)]
    assert len(lines) == 1
    assert "connected" in lines[0]


def test_e2e_life_005_worker_mdns_matches_master_record():
    status = run([
        "sg", "lattice-operator", "-c",
        f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}",
    ])
    status_output = _assert_ok(status, "operator worker status")
    ip_line = next(line for line in status_output.splitlines() if line.startswith("IP: ") )
    expected_ip = ip_line.split(":", 1)[1].strip()

    resolved = run(["getent", "hosts", f"{WORKER_HOST}.local"])
    resolved_output = _assert_ok(resolved, "worker mDNS resolution")
    assert resolved_output.split()[0] == expected_ip

def test_e2e_life_006_master_watchdog_active():
    result = run(["systemctl", "is-active", "lattice-health-watchdog.timer"])
    assert _assert_ok(result, "master health watchdog") == "active"


def test_e2e_file_002_file_daemons_active_on_both_hosts():
    master = run(["systemctl", "is-active", "lattice-file-sshd.service"])
    assert _assert_ok(master, "master file sshd") == "active"

    worker = ssh(WORKER_HOST, "systemctl is-active lattice-file-sshd.service")
    assert _assert_ok(worker, "worker file sshd") == "active"


def test_e2e_shell_002_shell_daemons_active_on_both_hosts():
    master = run(["systemctl", "is-active", "lattice-shell-sshd.service"])
    assert _assert_ok(master, "master shell sshd") == "active"

    worker = ssh(WORKER_HOST, "systemctl is-active lattice-shell-sshd.service")
    assert _assert_ok(worker, "worker shell sshd") == "active"
