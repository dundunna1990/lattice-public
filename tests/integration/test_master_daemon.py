"""Integration checks for the master daemon API.

Requests stay in-process through httpx's ASGI transport; no real socket is
bound and no service is started by these tests.
"""
import os

import httpx
import pytest_asyncio

from lattice.daemon.main import master_app


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=master_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


async def test_dashboard_with_valid_token(client):
    token = os.environ.get("LATTICE_API_TOKEN", "test-token-not-secret")
    response = await client.get("/api/dashboard", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text[:200]
    assert "<" in response.text and ">" in response.text


async def test_dashboard_with_no_token_returns_401(client):
    response = await client.get("/api/dashboard")
    assert response.status_code in (401, 403)


async def test_dashboard_with_bad_token_returns_403(client):
    response = await client.get("/api/dashboard", headers={"Authorization": "Bearer wrong-token-xyz"})
    assert response.status_code == 403


async def test_events_list_with_valid_token(client):
    token = os.environ.get("LATTICE_API_TOKEN", "test-token-not-secret")
    response = await client.get(
        "/api/events/list?limit=5", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200, response.text[:200]
    data = response.json()
    assert "events" in data
    assert isinstance(data["events"], list)


async def test_alerts_partial_with_valid_token(client):
    token = os.environ.get("LATTICE_API_TOKEN", "test-token-not-secret")
    response = await client.get("/api/alerts/partial", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text[:200]
    assert 'id="alerts-content"' in response.text


async def test_recheck_records_a_safe_request_and_refreshes_dashboard(client):
    token = os.environ.get("LATTICE_API_TOKEN", "test-token-not-secret")
    response = await client.post(
        "/api/workers/test-worker/recheck",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 204
    assert response.headers["HX-Trigger"] == "dashboardRefresh"
