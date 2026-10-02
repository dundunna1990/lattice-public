import sqlite3
import uuid

from lattice.backup.jobs import create_job, register_target
from lattice.core.migrations import run_migrations
from lattice import operator_interface


def _setup(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (node, "backup-node", "worker", "backupuser", 1000, 1000),
    )
    conn.commit(); conn.close()
    target = register_target(
        friendly_name="Backup Drive", host_node_id=node,
        filesystem_uuid="secret-device-id", repository_root="/mnt/private/LatticeBackups",
        target_type="local_storage",
    )
    job = create_job(source_node_id=node, target_id=target["id"], source_path="/home/backupuser")
    return job


def test_operator_backup_reads_are_friendly_and_do_not_expose_paths(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    jobs = operator_interface.execute_operator_request({"command": "backups.jobs", "params": {}})["data"]
    targets = operator_interface.execute_operator_request({"command": "backups.targets", "params": {}})["data"]
    assert jobs[0]["source_hostname"] == "backup-node"
    assert jobs[0]["target_name"] == "Backup Drive"
    assert "source_path" not in jobs[0]
    assert targets[0]["friendly_name"] == "Backup Drive"
    assert "repository_root" not in targets[0]
    assert "filesystem_uuid" not in targets[0]


def test_operator_backup_summary_is_read_only(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    summary = operator_interface.execute_operator_request({"command": "backups.summary", "params": {}})["data"]
    assert summary["state_counts"] == {"unknown": 1}


def test_operator_storage_candidates_hide_device_identity(tmp_path, monkeypatch):
    db = tmp_path / "candidates.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (node, "backup-node", "worker", "backupuser", 1000, 1000),
    )
    conn.execute(
        """INSERT INTO backup_storage_candidates(
               observer_node_id,filesystem_uuid,name,device,filesystem_type,
               mountpoint,size_bytes,removable,last_reported_at)
           VALUES(?,?,?,?,?,?,?,?,datetime('now'))""",
        (node, "disk-secret", "sdb1", "/dev/sdb1", "ext4", "/media/backup", 4_000_000_000_000, 1),
    )
    conn.commit(); conn.close()
    monkeypatch.setattr("lattice.backup.catalog.load_node_identity", lambda: None, raising=False)

    candidates = operator_interface.execute_operator_request(
        {"command": "backups.candidates", "params": {}}
    )["data"]
    assert len(candidates) == 1
    item = candidates[0]
    assert item["host_hostname"] == "backup-node"
    assert item["removable"] is True
    assert item["filesystem_type"] == "ext4"
    assert len(item["candidate_id"]) == 20
    assert "filesystem_uuid" not in item
    assert "device" not in item
    assert "mountpoint" not in item


def test_operator_marks_old_backup_observation_stale(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(__import__("os").environ["LATTICE_DB_PATH"])
    conn.execute(
        """INSERT INTO backup_job_observations(
               job_id,observer_node_id,state,last_result,last_reported_at)
           VALUES(?,?,?,?,?)""",
        (job["id"], job["source_node_id"], "healthy", "successful", "2000-01-01T00:00:00+00:00"),
    )
    conn.commit(); conn.close()
    jobs = operator_interface.execute_operator_request(
        {"command": "backups.jobs", "params": {}}
    )["data"]
    assert jobs[0]["state"] == "unknown"
    assert jobs[0]["reported_state"] == "healthy"
    assert jobs[0]["observation_stale"] is True
