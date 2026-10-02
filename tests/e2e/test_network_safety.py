"""Real-LAN unsafe-address and interrupted-network recovery tests."""
from __future__ import annotations

import shlex
import time

import pytest

from .conftest import WORKER_HOST, require_env, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _recorded_ip() -> str:
    result = run(["sg", "lattice-operator", "-c", f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
    assert result.returncode == 0
    return next(x.split(":", 1)[1].strip() for x in result.stdout.splitlines() if x.startswith("IP: "))


def _wait_healthy(expected_ip: str, timeout: int = 120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["sg", "lattice-operator", "-c", f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
        if result.returncode == 0 and "Status: healthy" in result.stdout and f"IP: {expected_ip}" in result.stdout:
            return
        time.sleep(3)
    pytest.fail("network safety test did not converge to the original healthy address")

def test_e2e_net_002_allocator_refuses_known_occupied_address():
    occupied = require_env("LATTICE_E2E_OCCUPIED_IP", "a known occupied LAN address")
    code = (
        "from lattice.pairing import _address_is_in_use; "
        "from lattice.ip_change.pool import read_address_pool; "
        "from lattice.pairing import _active_pool_interface; "
        "from lattice.core.config import load_config; "
        "p=read_address_pool(); c=load_config(); i=_active_pool_interface(p,c.master.ip); "
        f"print(_address_is_in_use(i,{occupied!r}))"
    )
    result = run(["sudo", "-n", "/opt/lattice/venv/bin/python", "-c", code], timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "True"


def test_e2e_net_003_interrupted_network_operation_recovers():
    injection = require_env(
        "LATTICE_E2E_NETWORK_INTERRUPT_COMMAND",
        "the lab-approved interrupted-network injection command",
    )
    expected = _recorded_ip()
    result = ssh(WORKER_HOST, injection, timeout=30)
    assert result.returncode == 0, result.stderr
    ssh(WORKER_HOST, "sudo -n systemctl start lattice-boot-recovery.service", timeout=30)
    ssh(WORKER_HOST, "sudo -n systemctl start lattice-network-reconcile.service", timeout=30)
    _wait_healthy(expected)
