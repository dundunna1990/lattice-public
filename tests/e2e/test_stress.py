"""Low-risk concurrency tests against the live two-machine fleet."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = pytest.mark.e2e


def _healthy_once(_: int) -> bool:
    result = run(["sg", "lattice-operator", "-c",
                  f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"], timeout=10)
    return result.returncode == 0 and "Status: healthy" in result.stdout


def test_e2e_stress_001_parallel_operator_reads_remain_healthy():
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(_healthy_once, range(48)))
    assert all(results)


def test_e2e_stress_002_parallel_worker_read_probes_succeed():
    def probe(_: int) -> bool:
        result = ssh(WORKER_HOST, "systemctl is-active lattice-worker.service", timeout=10)
        return result.returncode == 0 and result.stdout.strip() == "active"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(probe, range(24)))
    assert all(results)
