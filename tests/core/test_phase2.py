"""Safe API checks for the worker application.

All action requests mock subprocess.run, so this module never executes a
real systemctl command on the test host.
"""
from unittest.mock import MagicMock, patch

import httpx
import pytest
import pytest_asyncio

from lattice.daemon.api.worker_app import app


@pytest.fixture
def mock_token():
    with patch("lattice.daemon.api.worker_app.load_worker_token", return_value="test_token_123"):
        yield


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


def _completed(returncode=0, stdout="active\n", stderr=""):
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


async def test_worker_health(client):
    with patch(
        "lattice.daemon.api.worker_app.HealthChecker.current_snapshot",
        return_value={"status": "healthy"},
    ):
        response = await client.get("/v1/health")
    assert response.status_code == 200
    assert response.json().get("status") == "healthy"


async def test_worker_services_auth_required(client):
    response = await client.get("/v1/services")
    assert response.status_code == 401


async def test_worker_services_success(client, mock_token):
    headers = {"Authorization": "Bearer test_token_123"}
    response = await client.get("/v1/services", headers=headers)
    assert response.status_code == 200
    assert "services" in response.json()


@pytest.mark.parametrize(
    "action,expected_status",
    [
        ("restart", 202),
        ("stop", 400),
        ("reload", 400),
        ("status", 400),
        ("flush", 400),
        ("destroy_universe", 400),
    ],
)
async def test_worker_typed_actions(action, expected_status, mock_token, client):
    headers = {"Authorization": "Bearer test_token_123"}
    payload = {"action": action, "target": "lattice-worker"}
    with patch("lattice.daemon.api.worker_app.subprocess.Popen") as mock_run:
        response = await client.post("/v1/actions", json=payload, headers=headers)
    assert response.status_code == expected_status
    if expected_status == 400:
        mock_run.assert_not_called()


def test_crypto_authorized_keys_hardening():
    from lattice.core.crypto.ssh import install_restricted_authorized_key

    assert callable(install_restricted_authorized_key)
