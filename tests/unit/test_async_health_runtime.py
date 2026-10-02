import asyncio
import time
from types import SimpleNamespace
from unittest.mock import patch

from lattice.master.health_check import HealthCheckLoop


async def test_slow_worker_does_not_block_master_event_loop():
    class SlowAsyncClient:
        async def get(self, *_args, **_kwargs):
            await asyncio.sleep(0.20)
            raise RuntimeError(
                "simulated unreachable worker"
            )

        async def aclose(self):
            return None

        def close(self):
            return None

    worker = {
        "id": 1,
        "hostname": "slow-worker",
        "ip": "127.0.0.1",
        "ssh_user": "testuser",
    }

    loop = HealthCheckLoop(
        interval_seconds=10
    )
    loop._clients["slow-worker"] = (
        SlowAsyncClient()
    )

    async def ticker():
        started = time.perf_counter()
        await asyncio.sleep(0.05)
        return (
            time.perf_counter()
            - started
        )

    cfg = SimpleNamespace(
        wire_format=SimpleNamespace(
            port=9999
        )
    )

    with patch(
        "lattice.master.health_check.load_config",
        return_value=cfg,
    ), patch(
        "lattice.master.health_check.get_config_value",
        return_value="false",
    ), patch(
        "lattice.master.health_check.log_event",
    ), patch(
        "lattice.master.health_check.update_worker_state",
        return_value=SimpleNamespace(
            value="degraded"
        ),
    ):
        _, tick_delay = await asyncio.gather(
            loop._check_worker(worker),
            ticker(),
        )

    # If the event loop were synchronously blocked for 0.20s,
    # this 0.05s timer would not fire until after that block.
    assert tick_delay < 0.15
