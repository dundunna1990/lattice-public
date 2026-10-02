from pathlib import Path
from types import SimpleNamespace
import json
import sqlite3
import uuid

import pytest

from lattice.backup import manual
from lattice.backup.jobs import create_job, register_target
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch, *, remote=False, paused=False):
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    request = tmp_path / 'run-request.json'
    result = tmp_path / 'run-result.json'
    monkeypatch.setenv('LATTICE_BACKUP_RUN_REQUEST_PATH', str(request))
    monkeypatch.setenv('LATTICE_BACKUP_RUN_RESULT_PATH', str(result))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    source = str(uuid.uuid4())
    target_node = str(uuid.uuid4()) if remote else source
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (source, 'worker-node', 'worker', 'workeruser', 1000, 1000),
    )
    if remote:
        conn.execute(
            "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
            (target_node, 'backup-node', 'worker', 'backupuser', 1000, 1000),
        )
    conn.commit(); conn.close()
    target = register_target(
        friendly_name='Backup Drive', host_node_id=target_node,
        filesystem_uuid='disk-uuid', repository_root='/mnt/backup/LatticeBackups',
        target_type='local_storage',
    )
    job = create_job(
        source_node_id=source, target_id=target['id'], source_path='/home/workeruser'
    )
    if paused:
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE backup_jobs SET paused=1,pause_reason='Maintenance' WHERE id=?",
            (job['id'],),
        )
        conn.commit(); conn.close()
    monkeypatch.setattr(manual, 'load_node_identity', lambda: SimpleNamespace(node_id=source))
    return job, source, target_node, request, result


def test_queue_manual_backup_accepts_only_local_source_job(tmp_path, monkeypatch):
    job, _, _, request, _ = _setup(tmp_path, monkeypatch)
    assert manual.queue_manual_backup(job['job_uuid']) is True
    assert manual.queue_manual_backup(job['job_uuid']) is False
    payload = json.loads(request.read_text())
    assert payload['job_uuid'] == job['job_uuid']
    assert request.stat().st_mode & 0o777 == 0o600


def test_queue_manual_backup_rejects_paused_job(tmp_path, monkeypatch):
    job, _, _, _, _ = _setup(tmp_path, monkeypatch, paused=True)
    with pytest.raises(manual.ManualBackupError, match='resumed'):
        manual.queue_manual_backup(job['job_uuid'])


def test_root_manual_runner_uses_normal_remote_runner(tmp_path, monkeypatch):
    job, source, _, request, result_path = _setup(tmp_path, monkeypatch, remote=True)
    manual.queue_manual_backup(job['job_uuid'])
    monkeypatch.setattr(manual.os, 'geteuid', lambda: 0)
    called = []
    monkeypatch.setattr(
        manual, 'run_remote_job',
        lambda job_id, **kwargs: called.append((job_id, kwargs)) or {'snapshot_id': 'snap-1'},
    )
    monkeypatch.setattr(
        manual, 'run_local_job',
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('local runner used')),
    )
    output = manual.execute_manual_request()
    assert output['status'] == 'successful'
    assert output['snapshot_id'] == 'snap-1'
    assert called == [(job['id'], {'local_node_id': source, 'full_speed': False, 'allow_large_first_backup': False})]
    assert not request.exists()
    assert json.loads(result_path.read_text())['status'] == 'successful'


def test_root_manual_runner_revalidates_pause_after_queue(tmp_path, monkeypatch):
    job, _, _, request, _ = _setup(tmp_path, monkeypatch)
    manual.queue_manual_backup(job['job_uuid'])
    conn = sqlite3.connect(Path(__import__('os').environ['LATTICE_DB_PATH']))
    conn.execute(
        "UPDATE backup_jobs SET paused=1,pause_reason='Maintenance' WHERE id=?",
        (job['id'],),
    )
    conn.commit(); conn.close()
    monkeypatch.setattr(manual.os, 'geteuid', lambda: 0)
    with pytest.raises(manual.ManualBackupError, match='Paused backup'):
        manual.execute_manual_request()
    # Validation failure is terminal for this request; a future request can proceed.
    assert not request.exists()


def test_manual_large_backup_confirmation_reaches_runner(tmp_path, monkeypatch):
    job, source, _, request, _ = _setup(tmp_path, monkeypatch, remote=True)
    assert manual.queue_manual_backup(
        job["job_uuid"],
        allow_large_first_backup=True,
    ) is True
    payload = json.loads(request.read_text())
    assert payload["allow_large_first_backup"] is True

    monkeypatch.setattr(manual.os, "geteuid", lambda: 0)
    called = []
    monkeypatch.setattr(
        manual,
        "run_remote_job",
        lambda job_id, **kwargs: called.append((job_id, kwargs))
        or {"snapshot_id": "snap-confirmed"},
    )
    output = manual.execute_manual_request()

    assert output["snapshot_id"] == "snap-confirmed"
    assert called == [(
        job["id"],
        {
            "local_node_id": source,
            "full_speed": False,
            "allow_large_first_backup": True,
        },
    )]
