import sqlite3
from types import SimpleNamespace
import uuid

import pytest

from lattice.backup import observations
from lattice.backup.jobs import create_job, register_target, set_job_paused
from lattice.backup.observations import (
    BackupObservationError,
    backup_service_status,
    local_backup_observations,
    normalize_backup_observations,
)
from lattice.backup.runs import begin_run, finish_run
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (node, "worker-node", "worker", "workeruser", 1000, 1000),
    )
    conn.commit(); conn.close()
    target = register_target(
        friendly_name="Backup Drive", host_node_id=node,
        filesystem_uuid="disk-1", repository_root="/mnt/backup/LatticeBackups",
        target_type="local_storage",
    )
    job = create_job(source_node_id=node, target_id=target["id"], source_path="/home/workeruser")
    monkeypatch.setattr(observations, "load_node_identity", lambda: SimpleNamespace(node_id=node))
    return node, job


def test_local_observation_moves_from_never_backed_up_to_healthy(tmp_path, monkeypatch):
    node, job = _setup(tmp_path, monkeypatch)
    first = local_backup_observations()
    assert first[0]["state"] == "never_backed_up"
    run = begin_run(job["id"])
    finish_run(run["id"], result="successful", snapshot_id="snap")
    second = local_backup_observations()
    assert second[0]["observer_node_id"] == node
    assert second[0]["state"] == "healthy"
    assert backup_service_status(second) == "healthy"


def test_paused_backup_reports_degraded_service(tmp_path, monkeypatch):
    _, job = _setup(tmp_path, monkeypatch)
    set_job_paused(job["id"], paused=True, reason="Operator requested")
    payload = local_backup_observations()
    assert payload[0]["state"] == "paused"
    assert backup_service_status(payload) == "unhealthy"


def test_normalizer_rejects_wrong_observer_and_duplicates():
    node = str(uuid.uuid4())
    other = str(uuid.uuid4())
    item = {
        "observer_node_id": other,
        "job_uuid": str(uuid.uuid4()),
        "target_uuid": str(uuid.uuid4()),
        "state": "healthy",
        "last_result": "successful",
        "last_success_at": "2026-09-03T09:00:00+00:00",
    }
    with pytest.raises(BackupObservationError, match="wrong observer"):
        normalize_backup_observations([item], node)
    item["observer_node_id"] = node
    with pytest.raises(BackupObservationError, match="duplicated"):
        normalize_backup_observations([item, dict(item)], node)


def test_target_normalizer_rejects_offline_mount_claim():
    node = str(uuid.uuid4())
    payload = [{
        "observer_node_id": node,
        "target_uuid": str(uuid.uuid4()),
        "present": False,
        "filesystem_uuid": "disk-1",
        "mountpoint": "/mnt/backup",
        "total_bytes": None,
        "free_bytes": None,
        "health": "offline",
    }]
    with pytest.raises(BackupObservationError, match="must not claim"):
        observations.normalize_backup_target_observations(payload, node)


def test_target_normalizer_accepts_capacity_report():
    node = str(uuid.uuid4())
    payload = [{
        "observer_node_id": node,
        "target_uuid": str(uuid.uuid4()),
        "present": True,
        "filesystem_uuid": "disk-1",
        "mountpoint": "/mnt/backup",
        "total_bytes": 1000,
        "free_bytes": 600,
        "health": "healthy",
    }]
    normalized = observations.normalize_backup_target_observations(payload, node)
    assert normalized[0]["free_bytes"] == 600


def test_target_collection_uses_physical_uuid_mount_resolution(tmp_path, monkeypatch):
    node, _job = _setup(tmp_path, monkeypatch)

    from pathlib import Path
    from lattice.backup.models import MountIdentity
    from lattice.backup import targets

    monkeypatch.setattr(
        targets,
        "inspect_uuid_mount",
        lambda filesystem_uuid: MountIdentity(
            target=Path("/mnt/backup"),
            filesystem_uuid=filesystem_uuid,
            source="/dev/sda4",
            filesystem_type="ext4",
            options=frozenset({"rw", "relatime"}),
        ),
    )
    monkeypatch.setattr(
        observations.os if hasattr(observations, "os") else __import__("os"),
        "statvfs",
        lambda _path: SimpleNamespace(
            f_blocks=1000,
            f_frsize=4096,
            f_bavail=400,
        ),
    )

    payload = observations.local_backup_target_observations()

    assert payload[0]["observer_node_id"] == node
    assert payload[0]["present"] is True
    assert payload[0]["filesystem_uuid"] == "disk-1"
    assert payload[0]["mountpoint"] == "/mnt/backup"
    assert payload[0]["health"] == "healthy"
    assert payload[0]["total_bytes"] == 1000 * 4096
    assert payload[0]["free_bytes"] == 400 * 4096


def test_target_collection_error_reports_unknown_not_offline(tmp_path, monkeypatch):
    node, _job = _setup(tmp_path, monkeypatch)
    import subprocess
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("findmnt failed")),
    )
    payload = observations.local_backup_target_observations()
    assert payload
    assert payload[0]["observer_node_id"] == node
    assert payload[0]["present"] is False
    assert payload[0]["health"] == "unknown"
