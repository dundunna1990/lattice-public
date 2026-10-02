"""Real heartbeat/database contention tests."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _one_heartbeat():
    code = (
        "import asyncio; from lattice.core.config import load_config; "
        "from lattice.worker.health import HealthChecker; "
        "from lattice.worker.heartbeat import HeartbeatSender; "
        "s=HeartbeatSender(load_config(), HealthChecker()); "
        "asyncio.run(s.send_heartbeat())"
    )
    return ssh(
        WORKER_HOST,
        "sudo -n runuser -u lattice -- env "
        "LATTICE_DB_PATH=/var/lib/lattice/state.sqlite "
        "/opt/lattice/venv/bin/python -c " + repr(code),
        timeout=30,
    )


def test_e2e_stress_010_simultaneous_real_heartbeats_do_not_lock_db():
    since = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: _one_heartbeat(), range(24)))
    assert all(result.returncode == 0 for result in results), results
    journal = run([
        "journalctl", "-u", "lattice-master.service", "--since", since,
        "--no-pager", "-o", "cat",
    ], timeout=20)
    assert journal.returncode == 0, journal.stderr
    text = journal.stdout.lower()
    assert "database is locked" not in text
    assert "post /api/heartbeat" not in text or "500 internal server error" not in text

    status = run([
        "sg", "lattice-operator", "-c",
        f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}",
    ])
    assert status.returncode == 0, status.stderr
    assert "Status: healthy" in status.stdout
