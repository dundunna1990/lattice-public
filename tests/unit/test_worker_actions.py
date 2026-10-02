"""Safety tests for the worker's one permitted automatic repair."""
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest_asyncio

from lattice.daemon.api.worker_app import app, verify_token


@pytest_asyncio.fixture
async def client():
    async def fake_verify():
        return "test-token"
    app.dependency_overrides[verify_token] = fake_verify
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client
    app.dependency_overrides.pop(verify_token, None)


async def test_actions_refuse_everything_except_worker_restart(client):
    for action, target in (("stop", "lattice-worker"), ("restart", "sshd"), ("status", "lattice-worker")):
        response = await client.post("/v1/actions", json={"action": action, "target": target})
        assert response.status_code in (400, 403)


async def test_actions_do_not_launch_while_dry_run_is_enabled(client):
    config = SimpleNamespace(daemon=SimpleNamespace(dry_run=True))
    with patch("lattice.daemon.api.worker_app.load_config", return_value=config), \
         patch("lattice.daemon.api.worker_app.subprocess.Popen") as start:
        response = await client.post("/v1/actions", json={"action": "restart", "target": "lattice-worker"})
    assert response.status_code == 409
    start.assert_not_called()


async def test_actions_launches_only_the_restricted_helper(client):
    with patch("lattice.daemon.api.worker_app.subprocess.Popen") as start:
        response = await client.post("/v1/actions", json={"action": "restart", "target": "lattice-worker.service"})
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert start.call_args.args[0] == [
        "sudo", "-n", "/opt/lattice/bin/lattice-action-exec", "restart", "lattice-worker.service"
    ]


async def test_backup_run_endpoint_queues_only_validated_job_uuid(client):
    job_uuid = "11111111-1111-4111-8111-111111111111"
    with patch(
        "lattice.daemon.api.worker_app.queue_manual_backup",
        return_value=True,
    ) as queue:
        response = await client.post(
            "/v1/backups/run",
            json={"job_uuid": job_uuid},
        )
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    queue.assert_called_once_with(
        job_uuid,
        full_speed=False,
        allow_large_first_backup=False,
    )


async def test_backup_run_endpoint_reports_validation_failure(client):
    job_uuid = "11111111-1111-4111-8111-111111111111"
    from lattice.backup.manual import ManualBackupError
    with patch(
        "lattice.daemon.api.worker_app.queue_manual_backup",
        side_effect=ManualBackupError("Backup job belongs to a different source computer"),
    ):
        response = await client.post(
            "/v1/backups/run",
            json={"job_uuid": job_uuid},
        )
    assert response.status_code == 409
    assert "different source computer" in response.json()["detail"]


async def test_backup_query_endpoint_queues_read_only_request(client):
    job_uuid = "11111111-1111-4111-8111-111111111111"
    request_id = "22222222-2222-4222-8222-222222222222"
    with patch(
        "lattice.daemon.api.worker_app.queue_backup_query",
        return_value=request_id,
    ) as queue:
        response = await client.post(
            "/v1/backups/query",
            json={"job_uuid": job_uuid, "operation": "snapshots"},
        )
    assert response.status_code == 202
    assert response.json()["request_id"] == request_id
    queue.assert_called_once_with(
        job_uuid, "snapshots", snapshot_id=None, directory=None
    )


async def test_backup_query_result_reports_pending_or_completed(client):
    request_id = "22222222-2222-4222-8222-222222222222"
    with patch(
        "lattice.daemon.api.worker_app.read_backup_query_result",
        return_value=None,
    ):
        response = await client.get(f"/v1/backups/query-result/{request_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "pending"

    completed = {
        "request_id": request_id,
        "status": "successful",
        "operation": "snapshots",
        "snapshots": [],
    }
    with patch(
        "lattice.daemon.api.worker_app.read_backup_query_result",
        return_value=completed,
    ):
        response = await client.get(f"/v1/backups/query-result/{request_id}")
    assert response.status_code == 200
    assert response.json() == completed


async def test_backup_restore_endpoint_queues_only_typed_restore_request(client):
    job_uuid = "11111111-1111-4111-8111-111111111111"
    request_id = "66666666-6666-4666-8666-666666666666"
    with patch(
        "lattice.daemon.api.worker_app.queue_restore_request",
        return_value=request_id,
    ) as queue:
        response = await client.post(
            "/v1/backups/restore",
            json={
                "operation": "stage",
                "job_uuid": job_uuid,
                "snapshot_id": "snap-1",
                "selection": "/home/workeruser/file.txt",
            },
        )
    assert response.status_code == 202
    assert response.json()["request_id"] == request_id
    queue.assert_called_once_with(
        "stage",
        job_uuid=job_uuid,
        snapshot_id="snap-1",
        selection="/home/workeruser/file.txt",
        session_uuid=None,
        choice=None,
        elsewhere=None,
    )


async def test_backup_restore_result_reports_pending_or_completed(client):
    request_id = "66666666-6666-4666-8666-666666666666"
    with patch(
        "lattice.daemon.api.worker_app.read_restore_result",
        return_value=None,
    ):
        response = await client.get(f"/v1/backups/restore-result/{request_id}")
    assert response.status_code == 200
    assert response.json()["status"] == "pending"

    completed = {
        "request_id": request_id,
        "status": "successful",
        "destination": "/home/workeruser/file.txt",
    }
    with patch(
        "lattice.daemon.api.worker_app.read_restore_result",
        return_value=completed,
    ):
        response = await client.get(f"/v1/backups/restore-result/{request_id}")
    assert response.status_code == 200
    assert response.json() == completed


async def test_backup_recovery_preflight_query_is_read_only_typed_operation(client):
    job_uuid = "11111111-1111-4111-8111-111111111111"
    request_id = "77777777-7777-4777-8777-777777777777"
    with patch(
        "lattice.daemon.api.worker_app.queue_backup_query",
        return_value=request_id,
    ) as queue:
        response = await client.post(
            "/v1/backups/query",
            json={
                "job_uuid": job_uuid,
                "operation": "recovery_preflight",
                "snapshot_id": "snap-1",
            },
        )
    assert response.status_code == 202
    assert response.json()["request_id"] == request_id
    queue.assert_called_once_with(
        job_uuid,
        "recovery_preflight",
        snapshot_id="snap-1",
        directory=None,
    )


async def test_backup_run_endpoint_forwards_large_backup_confirmation(client):
    job_uuid = "11111111-1111-4111-8111-111111111111"
    with patch(
        "lattice.daemon.api.worker_app.queue_manual_backup",
        return_value=True,
    ) as queue:
        response = await client.post(
            "/v1/backups/run",
            json={
                "job_uuid": job_uuid,
                "allow_large_first_backup": True,
            },
        )
    assert response.status_code == 202
    queue.assert_called_once_with(
        job_uuid,
        full_speed=False,
        allow_large_first_backup=True,
    )
