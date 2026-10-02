from datetime import datetime, timedelta, timezone
import sqlite3
import uuid

import pytest

from lattice.core.migrations import run_migrations
from lattice.backup.jobs import create_job, register_target, set_job_paused
from lattice.backup.runs import BackupRunError, begin_run, finish_run, job_summary
from lattice.backup.scheduler import due_jobs, most_recent_schedule_boundary


def _setup(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (node, "master-node", "master", "masteruser", 1000, 1000),
    )
    conn.commit(); conn.close()
    target = register_target(friendly_name="Backup Drive", host_node_id=node, filesystem_uuid="disk-1", repository_root="/mnt/backup/LatticeBackups", target_type="local_storage")
    job = create_job(source_node_id=node, target_id=target["id"], source_path="/home/masteruser")
    return job


def test_run_lifecycle_and_friendly_summary(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    run = begin_run(job["id"])
    assert job_summary(job["id"])["state"] == "running"
    finished = finish_run(run["id"], result="successful", snapshot_id="abc123", bytes_added=42)
    assert finished["result"] == "successful"
    summary = job_summary(job["id"])
    assert summary["state"] == "healthy"
    assert summary["source_hostname"] == "master-node"
    assert summary["target_name"] == "Backup Drive"


def test_duplicate_running_job_is_blocked(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    begin_run(job["id"])
    with pytest.raises(BackupRunError, match="already running"):
        begin_run(job["id"])




def test_abandoned_running_job_can_be_reconciled_after_exclusive_lock(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    abandoned = begin_run(job["id"])
    replacement = begin_run(job["id"], recover_abandoned=True)
    db = __import__("pathlib").Path(__import__("os").environ["LATTICE_DB_PATH"])
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    old = conn.execute("SELECT * FROM backup_runs WHERE id=?", (abandoned["id"],)).fetchone()
    current = conn.execute("SELECT * FROM backup_runs WHERE id=?", (replacement["id"],)).fetchone()
    conn.close()
    assert old["result"] == "interrupted"
    assert old["error_code"] == "process_interrupted"
    assert old["finished_at"]
    assert current["result"] == "running"

def test_paused_job_is_not_due_or_runnable(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    set_job_paused(job["id"], paused=True, reason="Maintenance")
    assert due_jobs() == []
    with pytest.raises(BackupRunError, match="Maintenance"):
        begin_run(job["id"])


def test_never_backed_up_job_is_due(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    rows = due_jobs(now=datetime(2026, 9, 3, tzinfo=timezone.utc))
    assert [row["id"] for row in rows] == [job["id"]]


def test_recent_success_is_not_due(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    run = begin_run(job["id"])
    finished = finish_run(run["id"], result="successful")
    completed_at = datetime.fromisoformat(finished["finished_at"])
    assert due_jobs(now=completed_at + timedelta(minutes=1)) == []


def test_due_filter_limits_jobs_to_local_source(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    assert due_jobs(source_node_id=job["source_node_id"])
    assert due_jobs(source_node_id=str(uuid.uuid4())) == []


def test_catchup_does_not_move_nightly_boundary():
    tz = timezone(timedelta(hours=-7))
    now = datetime(2026, 9, 3, 14, 0, tzinfo=tz)
    boundary = most_recent_schedule_boundary(now)
    assert boundary == datetime(2026, 9, 3, 9, 0, tzinfo=timezone.utc)


def test_before_two_am_uses_previous_night_boundary():
    tz = timezone(timedelta(hours=-7))
    now = datetime(2026, 9, 3, 1, 30, tzinfo=tz)
    boundary = most_recent_schedule_boundary(now)
    assert boundary == datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)
