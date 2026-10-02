import asyncio
import sqlite3
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from lattice.api.routes.heartbeat import _begin_heartbeat_transaction
from lattice.master.health_check import HealthCheckLoop


async def test_heartbeat_begin_retries_short_sqlite_contention():
    class Conn:
        def __init__(self):
            self.begin_calls = 0
            self.pragmas = []

        async def execute(self, sql):
            if sql.startswith("PRAGMA"):
                self.pragmas.append(sql)
                return None
            if sql == "BEGIN IMMEDIATE":
                self.begin_calls += 1
                if self.begin_calls < 3:
                    raise sqlite3.OperationalError("database is locked")
                return None
            raise AssertionError(sql)

    conn = Conn()
    await _begin_heartbeat_transaction(conn)
    assert conn.begin_calls == 3
    assert conn.pragmas == ["PRAGMA busy_timeout=1000"]


async def test_master_db_contention_does_not_mark_healthy_worker_failed():
    class HealthyClient:
        async def get(self, *_args, **_kwargs):
            response = MagicMock()
            response.status_code = 200
            response.json.return_value = {
                "status": "healthy",
                "instance_id": "instance-1",
            }
            return response

        async def aclose(self):
            return None

        def close(self):
            return None

    class BusyConn:
        async def execute(self, *_args, **_kwargs):
            raise sqlite3.OperationalError("database is locked")

        async def commit(self):
            return None

        async def close(self):
            return None

    worker = {
        "id": 1,
        "hostname": "healthy-worker",
        "ip": "10.77.0.50",
        "ssh_user": "test",
    }
    loop = HealthCheckLoop(interval_seconds=10)
    loop._clients["healthy-worker"] = HealthyClient()

    with patch(
        "lattice.master.health_check.load_config",
        return_value=SimpleNamespace(wire_format=SimpleNamespace(port=9999)),
    ), patch(
        "lattice.master.health_check.get_config_value",
        return_value="false",
    ), patch(
        "lattice.master.health_check.get_async_db_connection",
        AsyncMock(return_value=BusyConn()),
    ), patch(
        "lattice.master.health_check.update_worker_state"
    ) as update_state, patch.object(
        loop, "_record_failure"
    ) as record_failure:
        await loop._check_worker(worker)

    update_state.assert_not_called()
    record_failure.assert_not_called()
    assert "healthy-worker" not in loop._backoff_state
