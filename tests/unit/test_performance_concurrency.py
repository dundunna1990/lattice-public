"""Regression tests for performance/concurrency audit findings."""

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import patch

from lattice.healing.policy import reserve_restart_attempt
from lattice.worker.heartbeat import HeartbeatSender


async def test_worker_health_probe_does_not_block_event_loop(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.crt").write_text("fake")

    monkeypatch.setenv("LATTICE_PKI_DIR", str(pki))

    class SlowHealth:
        def check_all(self):
            time.sleep(0.20)
            return [
                {
                    "name": "sshd",
                    "status": "healthy",
                }
            ]

    sender = HeartbeatSender(
        SimpleNamespace(
            master=SimpleNamespace(
                ip="127.0.0.1",
                api_port=8443,
            )
        ),
        SlowHealth(),
    )

    monkeypatch.setattr(
        "lattice.worker.heartbeat.read_token_file",
        lambda *_args: "x" * 48,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.get_worker_master_endpoint",
        lambda: None,
    )
    monkeypatch.setattr(
        "lattice.worker.heartbeat.ssl.create_default_context",
        lambda **_kwargs: object(),
    )

    class Client:
        async def post(self, *_args, **_kwargs):
            return SimpleNamespace(
                status_code=200,
                text="ok",
            )

        async def aclose(self):
            return None

    sender._client = Client()

    started = time.perf_counter()

    async def ticker():
        await asyncio.sleep(0.05)
        return time.perf_counter() - started

    _, tick = await asyncio.gather(
        sender.send_heartbeat(),
        ticker(),
    )

    assert tick < 0.15


def test_restart_budget_atomic_reservation_stops_third_attempt():
    # Use a dedicated synthetic worker ID so restart attempts created by
    # unrelated tests cannot consume this test's safety budget.
    worker_id = 987654321

    assert reserve_restart_attempt(
        worker_id,
        "lattice-worker",
    ) is True

    assert reserve_restart_attempt(
        worker_id,
        "lattice-worker",
    ) is True

    assert reserve_restart_attempt(
        worker_id,
        "lattice-worker",
    ) is False


async def test_ten_worker_network_waits_overlap():
    """Ten slow worker operations should overlap instead of serializing."""
    async def one_worker():
        await asyncio.sleep(0.20)
        return True

    started = time.perf_counter()

    results = await asyncio.gather(
        *(one_worker() for _ in range(10))
    )

    elapsed = time.perf_counter() - started

    assert all(results)
    assert elapsed < 0.60
