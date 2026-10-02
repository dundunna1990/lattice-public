"""Regression coverage for confirmed repository-audit repairs."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from lattice.api.routes.workers import recheck_worker
from lattice.core.daemon import DEFAULT_SOCKET_PATH
from lattice.core.pki import PKIError, tls_server_options
from lattice.daemon.api.worker_app import load_worker_token
from lattice.daemon.main import master_app


def test_worker_token_loader_uses_safe_path_reader(tmp_path, monkeypatch):
    token_path = tmp_path / "worker.token"
    token_path.write_text("x" * 48 + "\n")
    token_path.chmod(0o600)
    monkeypatch.setenv("LATTICE_TOKEN_PATH", str(token_path))
    assert load_worker_token() == "x" * 48


def test_daemon_reload_default_matches_production_socket():
    assert DEFAULT_SOCKET_PATH == "/run/lattice/master.sock"


def test_tls_server_refuses_plaintext_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("LATTICE_PKI_DIR", str(tmp_path / "missing-pki"))
    with pytest.raises(PKIError, match="TLS identity is missing"):
        tls_server_options("master")


@pytest.mark.asyncio
async def test_web_recheck_sets_health_loop_flag():
    conn = MagicMock()
    cursor = MagicMock()
    cursor.fetchone = AsyncMock(
        return_value=(7,)
    )
    conn.execute = AsyncMock(
        return_value=cursor
    )
    conn.close = AsyncMock()

    with patch(
        "lattice.api.routes.workers.get_async_db_connection",
        AsyncMock(return_value=conn),
    ), patch(
        "lattice.core.config.set_config_value"
    ) as set_value, patch(
        "lattice.api.routes.workers.log_event"
    ):
        response = await recheck_worker(
            "worker-one"
        )

    set_value.assert_called_once_with(
        "health.recheck.7",
        "true",
    )
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_browser_partial_routes_render_html():
    transport = httpx.ASGITransport(app=master_app)
    headers = {"Authorization": "Bearer test-token-not-secret"}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        events = await client.get("/api/events/partial?limit=5", headers=headers)
        worker = await client.get("/api/workers/test-worker/partial", headers=headers)
    assert events.status_code == 200
    assert "text/html" in events.headers["content-type"]
    assert 'id="events-content"' in events.text
    assert worker.status_code == 200
    assert "text/html" in worker.headers["content-type"]
    assert 'id="worker-detail"' in worker.text
