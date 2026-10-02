from types import SimpleNamespace
import json
import sqlite3
import uuid

import pytest

from lattice.backup import restore_request
from lattice.backup.jobs import create_job, register_target
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(
        restore_request.grp,
        'getgrnam',
        lambda name: SimpleNamespace(gr_gid=999) if name == 'lattice' else (_ for _ in ()).throw(KeyError(name)),
    )
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    monkeypatch.setenv('LATTICE_BACKUP_RESTORE_REQUEST_PATH', str(tmp_path / 'restore-request.json'))
    monkeypatch.setenv('LATTICE_BACKUP_RESTORE_RESULT_PATH', str(tmp_path / 'restore-result.json'))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    source = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (source, 'worker-node', 'worker', 'workeruser', 1000, 1000),
    )
    conn.commit(); conn.close()
    target = register_target(
        friendly_name='Backup Drive', host_node_id=source,
        filesystem_uuid='disk-uuid', repository_root='/mnt/backup/LatticeBackups',
        target_type='local_storage',
    )
    job = create_job(
        source_node_id=source, target_id=target['id'], source_path='/home/workeruser'
    )
    monkeypatch.setattr(
        restore_request, 'load_node_identity', lambda: SimpleNamespace(node_id=source)
    )
    return job


def test_queue_stage_request_is_narrow_and_source_owned(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    request_id = restore_request.queue_restore_request(
        'stage',
        job_uuid=job['job_uuid'],
        snapshot_id='snapshot-1',
        selection='/home/workeruser/Documents/file.txt',
    )
    payload = json.loads((tmp_path / 'restore-request.json').read_text())
    assert payload['request_id'] == request_id
    assert payload['operation'] == 'stage'
    assert payload['job_uuid'] == job['job_uuid']
    assert payload['selection'] == '/home/workeruser/Documents/file.txt'


def test_queue_place_requires_explicit_choice(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    session = str(uuid.uuid4())
    with pytest.raises(restore_request.BackupRestoreRequestError, match='choice'):
        restore_request.queue_restore_request(
            'place', session_uuid=session, choice='overwrite_everything'
        )


def test_execute_stage_records_success_result(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    request_id = restore_request.queue_restore_request(
        'stage', job_uuid=job['job_uuid'], snapshot_id='snapshot-1',
        selection='/home/workeruser/file.txt',
    )
    monkeypatch.setattr(restore_request.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(restore_request.os, 'chown', lambda *args: None)
    monkeypatch.setattr(
        restore_request,
        'stage_restore',
        lambda *args: {
            'status': 'staged',
            'session_uuid': str(uuid.uuid4()),
            'conflict': True,
            'original_destination': '/home/workeruser/file.txt',
        },
    )
    result = restore_request.execute_restore_request()
    assert result['status'] == 'successful'
    assert result['request_id'] == request_id
    saved = json.loads((tmp_path / 'restore-result.json').read_text())
    assert saved['status'] == 'successful'
    assert not (tmp_path / 'restore-request.json').exists()


def test_execute_failure_records_failed_result_and_clears_request(tmp_path, monkeypatch):
    job = _setup(tmp_path, monkeypatch)
    request_id = restore_request.queue_restore_request(
        'stage', job_uuid=job['job_uuid'], snapshot_id='snapshot-1',
        selection='/home/workeruser/file.txt',
    )
    monkeypatch.setattr(restore_request.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(restore_request.os, 'chown', lambda *args: None)
    monkeypatch.setattr(
        restore_request,
        'stage_restore',
        lambda *args: (_ for _ in ()).throw(RuntimeError('simulated restore failure')),
    )
    with pytest.raises(restore_request.BackupRestoreRequestError, match='simulated'):
        restore_request.execute_restore_request()
    saved = json.loads((tmp_path / 'restore-result.json').read_text())
    assert saved['request_id'] == request_id
    assert saved['status'] == 'failed'
    assert 'simulated restore failure' in saved['error']
    assert not (tmp_path / 'restore-request.json').exists()
