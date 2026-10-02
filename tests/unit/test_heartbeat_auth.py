"""The master authenticates each heartbeat with that worker's own token."""

import httpx
import pytest_asyncio
from fastapi import FastAPI

from lattice.api.routes.heartbeat import router
from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations


@pytest_asyncio.fixture
async def heartbeat_client(tmp_path, monkeypatch):
    monkeypatch.setenv("LATTICE_DB_PATH", str(tmp_path / "master.db"))
    token_dir = tmp_path / "tokens"
    token_dir.mkdir()
    monkeypatch.setenv("LATTICE_TOKEN_DIR", str(token_dir))
    token = "w" * 48
    token_path = token_dir / "worker-one.token"
    token_path.write_text(token + "\n")
    token_path.chmod(0o600)
    conn = get_db_connection()
    run_migrations(conn)
    conn.execute("INSERT INTO workers (hostname, status) VALUES ('worker-one', 'healthy')")
    conn.commit()
    conn.close()
    app = FastAPI()
    app.include_router(router)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client, token


async def test_heartbeat_accepts_only_the_saved_per_worker_token(heartbeat_client):
    client, token = heartbeat_client
    accepted = await client.post(
        "/api/heartbeat",
        json={"hostname": "worker-one"},
        headers={"Authorization": f"Bearer {token}"},
    )
    wrong = await client.post(
        "/api/heartbeat",
        json={"hostname": "worker-one"},
        headers={"Authorization": "Bearer test-token-not-secret"},
    )
    unknown = await client.post(
        "/api/heartbeat",
        json={"hostname": "worker-two"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert accepted.status_code == 200
    assert wrong.status_code == 403
    assert unknown.status_code == 403


async def test_heartbeat_persists_fresh_service_evidence(heartbeat_client):
    client, token = heartbeat_client
    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "services": [{"name": "lattice-worker", "status": "unhealthy"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    conn = get_db_connection()
    row = conn.execute(
        "SELECT status, last_reported_at FROM services WHERE name = 'lattice-worker'"
    ).fetchone()
    conn.close()
    assert row[0] == "unhealthy"
    assert row[1]


async def test_degraded_heartbeat_marks_healthy_worker_degraded_without_failure_increment(
    heartbeat_client,
):
    client, token = heartbeat_client

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "degraded",
            "services": [
                {"name": "sshd", "status": "unhealthy"}
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    conn = get_db_connection()
    row = conn.execute(
        "SELECT status, failure_count FROM workers WHERE hostname = 'worker-one'"
    ).fetchone()
    conn.close()

    assert row[0] == "degraded"
    assert row[1] == 0


async def test_healthy_heartbeat_clears_only_service_only_degradation(
    heartbeat_client,
):
    client, token = heartbeat_client

    conn = get_db_connection()
    conn.execute(
        """
        UPDATE workers
        SET status = 'degraded', failure_count = 0
        WHERE hostname = 'worker-one'
        """
    )
    conn.commit()
    conn.close()

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "healthy",
            "services": [
                {"name": "sshd", "status": "healthy"}
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    conn = get_db_connection()
    row = conn.execute(
        "SELECT status, failure_count FROM workers WHERE hostname = 'worker-one'"
    ).fetchone()
    conn.close()

    assert row[0] == "healthy"
    assert row[1] == 0


async def test_healthy_heartbeat_cannot_erase_master_reachability_failure(
    heartbeat_client,
):
    client, token = heartbeat_client

    conn = get_db_connection()
    conn.execute(
        """
        UPDATE workers
        SET status = 'degraded', failure_count = 1
        WHERE hostname = 'worker-one'
        """
    )
    conn.commit()
    conn.close()

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "healthy",
            "services": [
                {"name": "sshd", "status": "healthy"}
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    conn = get_db_connection()
    row = conn.execute(
        "SELECT status, failure_count FROM workers WHERE hostname = 'worker-one'"
    ).fetchone()
    conn.close()

    assert row[0] == "degraded"
    assert row[1] == 1


async def test_heartbeat_never_clears_master_down_state(
    heartbeat_client,
):
    client, token = heartbeat_client

    conn = get_db_connection()
    conn.execute(
        """
        UPDATE workers
        SET status = 'down', failure_count = 3
        WHERE hostname = 'worker-one'
        """
    )
    conn.commit()
    conn.close()

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "healthy",
            "services": [
                {"name": "sshd", "status": "healthy"}
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    conn = get_db_connection()
    row = conn.execute(
        "SELECT status, failure_count FROM workers WHERE hostname = 'worker-one'"
    ).fetchone()
    conn.close()

    assert row[0] == "down"
    assert row[1] == 3


async def test_recovery_heartbeat_bypasses_old_down_backoff_once(
    heartbeat_client,
):
    client, token = heartbeat_client

    conn = get_db_connection()
    conn.execute(
        """
        UPDATE workers
        SET status = 'down', failure_count = 9,
            last_heartbeat_at = datetime('now', '-5 minutes')
        WHERE hostname = 'worker-one'
        """
    )
    worker_id = conn.execute(
        "SELECT id FROM workers WHERE hostname = 'worker-one'"
    ).fetchone()[0]
    conn.commit()
    conn.close()

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "healthy",
            "services": [{"name": "sshd", "status": "healthy"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    conn = get_db_connection()
    worker = conn.execute(
        "SELECT status, failure_count FROM workers WHERE id = ?",
        (worker_id,),
    ).fetchone()
    recheck = conn.execute(
        "SELECT value FROM config WHERE key = ?",
        (f"health.recheck.{worker_id}",),
    ).fetchone()
    assert worker[0] == "down"
    assert worker[1] == 9
    assert recheck[0] == "true"

    conn.execute(
        "UPDATE config SET value = 'false' WHERE key = ?",
        (f"health.recheck.{worker_id}",),
    )
    conn.commit()
    conn.close()

    second = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "healthy",
            "services": [{"name": "sshd", "status": "healthy"}],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert second.status_code == 200

    conn = get_db_connection()
    recheck = conn.execute(
        "SELECT value FROM config WHERE key = ?",
        (f"health.recheck.{worker_id}",),
    ).fetchone()
    conn.close()
    assert recheck[0] == "false"


async def test_failed_service_overrides_inconsistent_healthy_top_level_status(
    heartbeat_client,
):
    client, token = heartbeat_client

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "healthy",
            "services": [
                {"name": "sshd", "status": "unhealthy"}
            ],
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200

    conn = get_db_connection()
    row = conn.execute(
        "SELECT status FROM workers WHERE hostname = 'worker-one'"
    ).fetchone()
    conn.close()

    assert row[0] == "degraded"


async def test_invalid_top_level_heartbeat_status_is_rejected(
    heartbeat_client,
):
    client, token = heartbeat_client

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "status": "down",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400


def _install_active_fleet_worker(
    *,
    current_generation: int,
    worker_generation: int,
):
    import json

    conn = get_db_connection()

    worker = conn.execute(
        """
        SELECT id
        FROM workers
        WHERE hostname = 'worker-one'
        """
    ).fetchone()

    assert worker is not None

    conn.execute(
        """
        INSERT INTO fleet_nodes (
            node_id,
            worker_id,
            hostname,
            role,
            main_user,
            main_uid,
            main_gid,
            membership_state,
            membership_generation
        )
        VALUES (
            '11111111-1111-4111-8111-111111111111',
            ?,
            'worker-one',
            'worker',
            'testuser',
            1000,
            1000,
            'active',
            ?
        )
        """,
        (
            worker[0],
            worker_generation,
        ),
    )

    manifest = {
        "schema_version": 1,
        "fleet_id":
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "generation": current_generation,
        "members": [],
        "revoked": [],
    }

    conn.execute(
        """
        INSERT INTO fleet_state (
            id,
            fleet_id,
            generation,
            manifest,
            signature,
            signing_public_key
        )
        VALUES (
            1,
            ?,
            ?,
            ?,
            'signed-generation-test',
            'ssh-ed25519 test-key'
        )
        """,
        (
            manifest["fleet_id"],
            current_generation,
            json.dumps(manifest),
        ),
    )

    conn.commit()
    conn.close()

    return manifest


async def test_heartbeat_returns_signed_manifest_when_worker_is_behind(
    heartbeat_client,
):
    client, token = heartbeat_client

    manifest = _install_active_fleet_worker(
        current_generation=3,
        worker_generation=2,
    )

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": 2,
        },
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["fleet_generation"] == 3
    assert payload["fleet_update"] == {
        "manifest": manifest,
        "signature": "signed-generation-test",
    }

    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT membership_generation
        FROM fleet_nodes
        WHERE hostname = 'worker-one'
        """
    ).fetchone()
    conn.close()

    # It was already known to have generation 2.
    assert row[0] == 2


async def test_heartbeat_acknowledges_worker_caught_up(
    heartbeat_client,
):
    client, token = heartbeat_client

    _install_active_fleet_worker(
        current_generation=3,
        worker_generation=2,
    )

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": 3,
        },
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["fleet_generation"] == 3
    assert "fleet_update" not in payload

    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT membership_generation
        FROM fleet_nodes
        WHERE hostname = 'worker-one'
        """
    ).fetchone()
    conn.close()

    assert row[0] == 3


async def test_heartbeat_rejects_generation_newer_than_master(
    heartbeat_client,
):
    client, token = heartbeat_client

    _install_active_fleet_worker(
        current_generation=3,
        worker_generation=2,
    )

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": 4,
        },
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 409


async def test_heartbeat_rejects_invalid_fleet_generation(
    heartbeat_client,
):
    client, token = heartbeat_client

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": True,
        },
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 400


async def test_heartbeat_returns_current_mount_locator_plan(
    heartbeat_client,
    monkeypatch,
):
    client, token = heartbeat_client

    _install_active_fleet_worker(
        current_generation=3,
        worker_generation=3,
    )

    expected = {
        "generation":
            3,
        "peers":
            [
                {
                    "node_id":
                        "11111111-1111-4111-8111-111111111111",
                    "hostname":
                        "worker-one",
                    "ip":
                        "10.77.0.201",
                    "remote_user":
                        "testuser",
                    "port":
                        22022,
                }
            ],
    }

    monkeypatch.setattr(
        "lattice.api.routes.heartbeat."
        "build_mount_plan",
        lambda *args, **kwargs:
            expected,
    )

    monkeypatch.setattr(
        "lattice.api.routes.heartbeat."
        "write_mount_plan",
        lambda *args, **kwargs:
            True,
    )

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname":
                "worker-one",
            "fleet_generation":
                3,
        },
        headers={
            "Authorization":
                f"Bearer {token}"
        },
    )

    assert response.status_code == 200

    assert response.json()[
        "mount_plan"
    ] == expected


async def test_heartbeat_replaces_current_backup_storage_candidates(heartbeat_client):
    client, token = heartbeat_client
    node_id = "11111111-1111-4111-8111-111111111111"
    conn = get_db_connection()
    worker_id = conn.execute(
        "SELECT id FROM workers WHERE hostname='worker-one'"
    ).fetchone()[0]
    conn.execute(
        """INSERT INTO fleet_nodes(
               node_id,worker_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?,?, 'active')""",
        (node_id, worker_id, "worker-one", "worker", "user", 1000, 1000),
    )
    conn.commit(); conn.close()

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": 0,
            "backup_storage_candidates": [{
                "observer_node_id": node_id,
                "name": "sdb1",
                "device": "/dev/sdb1",
                "filesystem_uuid": "drive-uuid",
                "filesystem_type": "ext4",
                "mountpoint": "/media/backup",
                "size_bytes": 4_000_000_000_000,
                "removable": True,
            }],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    conn = get_db_connection()
    row = conn.execute(
        "SELECT filesystem_uuid,mountpoint,removable FROM backup_storage_candidates"
    ).fetchone()
    conn.close()
    assert tuple(row) == ("drive-uuid", "/media/backup", 1)

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": 0,
            "backup_storage_candidates": [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    conn = get_db_connection()
    count = conn.execute(
        "SELECT COUNT(*) FROM backup_storage_candidates"
    ).fetchone()[0]
    conn.close()
    assert count == 0


async def test_heartbeat_persists_daily_care_observation(heartbeat_client):
    client, token = heartbeat_client
    _install_active_fleet_worker(current_generation=3, worker_generation=3)

    response = await client.post(
        "/api/heartbeat",
        json={
            "hostname": "worker-one",
            "fleet_generation": 3,
            "care_observation": {
                "node_id": "11111111-1111-4111-8111-111111111111",
                "hostname": "worker-one",
                "status": "attention",
                "last_run_at": "2026-09-05T10:00:00+00:00",
                "bytes_reclaimed": 1234,
                "attention_count": 1,
                "critical_count": 0,
                "deferred_reason": None,
                "findings": [{
                    "severity": "attention",
                    "code": "reboot.required",
                    "subject": "Reboot required",
                    "detail": "Installed updates require a reboot.",
                }],
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    conn = get_db_connection()
    row = conn.execute(
        """SELECT hostname,status,last_run_at,bytes_reclaimed,
                  attention_count,critical_count,findings_json
           FROM care_observations
           WHERE node_id='11111111-1111-4111-8111-111111111111'"""
    ).fetchone()
    conn.close()

    assert row[0] == "worker-one"
    assert row[1] == "attention"
    assert row[2] == "2026-09-05T10:00:00+00:00"
    assert row[3] == 1234
    assert row[4] == 1
    assert row[5] == 0
    assert "reboot.required" in row[6]
