from types import SimpleNamespace
import sqlite3
import uuid

from lattice.backup import control
from lattice.backup.jobs import create_job, register_target
from lattice.core.migrations import run_migrations


def _db(tmp_path, monkeypatch, *, remote=False):
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    source = str(uuid.uuid4())
    master = str(uuid.uuid4())
    target_node = master if remote else source
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (master, 'master-node', 'master', 'masteruser', 1000, 1000),
    )
    if remote:
        conn.execute(
            "INSERT INTO workers(hostname,status,ip,ssh_user) VALUES('worker-node','healthy','10.0.0.2','workeruser')"
        )
        worker_id = conn.execute("SELECT id FROM workers WHERE hostname='worker-node'").fetchone()[0]
        conn.execute(
            "INSERT INTO fleet_nodes(node_id,worker_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?,?, 'active')",
            (source, worker_id, 'worker-node', 'worker', 'workeruser', 1000, 1000),
        )
    else:
        # Local source and target host are the master identity in this fixture.
        source = master
        target_node = master
    conn.commit(); conn.close()
    target = register_target(
        friendly_name='Backup Drive', host_node_id=target_node,
        filesystem_uuid='disk-uuid', repository_root='/mnt/backup/LatticeBackups',
        target_type='local_storage',
    )
    job = create_job(
        source_node_id=source, target_id=target['id'],
        source_path='/home/workeruser' if remote else '/home/masteruser',
    )
    monkeypatch.setattr(control, 'load_node_identity', lambda: SimpleNamespace(node_id=master))
    return job, source, master


def test_run_now_local_queues_only_job_uuid(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    calls = []
    monkeypatch.setattr(
        control, 'queue_manual_backup',
        lambda job_uuid, **kwargs: calls.append((job_uuid, kwargs)) or True,
    )
    result = control.run_backup_now(job['job_uuid'])
    assert result['status'] == 'accepted'
    assert calls == [(job['job_uuid'], {'full_speed': False, 'allow_large_first_backup': False})]


def test_run_now_remote_routes_to_authenticated_worker_client(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=True)
    calls = []

    async def fake_request(data, **kwargs):
        calls.append((data['job_uuid'], kwargs))
        return {'status': 'accepted'}

    monkeypatch.setattr(control, '_request_worker_run', fake_request)
    result = control.run_backup_now(job['job_uuid'])
    assert result['status'] == 'accepted'
    assert calls == [(job['job_uuid'], {'full_speed': False, 'allow_large_first_backup': False})]


def test_setup_existing_target_uses_home_only_helper(tmp_path, monkeypatch):
    db = tmp_path / 'setup.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    conn = sqlite3.connect(db); run_migrations(conn)
    source = str(uuid.uuid4())
    host = str(uuid.uuid4())
    for node, name, user in (
        (source, 'worker-node', 'workeruser'),
        (host, 'backup-node', 'backupuser'),
    ):
        conn.execute(
            "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
            (node, name, 'worker', user, 1000, 1000),
        )
    conn.commit(); conn.close()
    target = register_target(
        friendly_name='Backup Drive', host_node_id=host,
        filesystem_uuid='disk-uuid', repository_root='/mnt/backup/LatticeBackups',
        target_type='local_storage',
    )
    result = control.setup_backup(
        source, 'target', str(target['id']), 'Backup Drive'
    )
    assert result['status'] == 'created'
    conn = sqlite3.connect(db)
    source_path = conn.execute(
        'SELECT source_path FROM backup_jobs WHERE id=?', (result['job_id'],)
    ).fetchone()[0]
    conn.close()
    assert source_path == '/home/workeruser'


def test_query_backup_local_uses_local_query_watcher(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    monkeypatch.setattr(
        control, 'queue_backup_query',
        lambda job_uuid, operation, **kwargs: '33333333-3333-4333-8333-333333333333',
    )
    monkeypatch.setattr(
        control, 'wait_for_query_result',
        lambda request_id, timeout_seconds=0: {
            'status': 'successful',
            'request_id': request_id,
            'source_root': '/home/masteruser',
            'snapshots': [],
        },
    )
    result = control.query_backup(job['job_uuid'], 'snapshots')
    assert result['status'] == 'successful'
    assert result['source_root'] == '/home/masteruser'


def test_query_backup_remote_uses_authenticated_worker_query(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=True)
    calls = []

    async def fake_query(data, operation, **kwargs):
        calls.append((data['job_uuid'], operation, kwargs))
        return {
            'status': 'successful',
            'source_root': '/home/workeruser',
            'snapshots': [],
        }

    monkeypatch.setattr(control, '_request_worker_query', fake_query)
    result = control.query_backup(job['job_uuid'], 'snapshots')
    assert result['status'] == 'successful'
    assert calls == [(job['job_uuid'], 'snapshots', {'snapshot_id': None, 'directory': None})]


def test_restore_backup_local_uses_local_restore_queue(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    request_id = '44444444-4444-4444-8444-444444444444'
    monkeypatch.setattr(
        control, 'queue_restore_request',
        lambda operation, **kwargs: request_id,
    )
    monkeypatch.setattr(
        control, 'wait_for_restore_result',
        lambda rid, timeout_seconds=0: {
            'status': 'successful',
            'request_id': rid,
            'session_uuid': '55555555-5555-4555-8555-555555555555',
            'conflict': True,
        },
    )
    result = control.restore_backup(
        job['job_uuid'], 'stage', snapshot_id='snap-1', selection='/home/masteruser/file.txt'
    )
    assert result['status'] == 'successful'
    assert result['request_id'] == request_id


def test_restore_backup_remote_routes_to_worker_restore_api(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=True)
    calls = []

    async def fake_restore(data, payload):
        calls.append((data['job_uuid'], payload))
        return {
            'status': 'successful',
            'session_uuid': '55555555-5555-4555-8555-555555555555',
        }

    monkeypatch.setattr(control, '_request_worker_restore', fake_restore)
    result = control.restore_backup(
        job['job_uuid'], 'stage', snapshot_id='snap-1',
        selection='/home/workeruser/file.txt'
    )
    assert result['status'] == 'successful'
    assert calls[0][0] == job['job_uuid']
    assert calls[0][1]['operation'] == 'stage'
    assert calls[0][1]['snapshot_id'] == 'snap-1'
    assert calls[0][1]['selection'] == '/home/workeruser/file.txt'


def test_restore_backup_can_place_while_job_is_paused(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    conn = sqlite3.connect(tmp_path / 'state.sqlite')
    conn.execute(
        "UPDATE backup_jobs SET paused=1,pause_reason='Maintenance' WHERE id=?",
        (job['id'],),
    )
    conn.commit(); conn.close()
    monkeypatch.setattr(
        control, 'queue_restore_request',
        lambda operation, **kwargs: '44444444-4444-4444-8444-444444444444',
    )
    monkeypatch.setattr(
        control, 'wait_for_restore_result',
        lambda *args, **kwargs: {
            'status': 'successful', 'destination': '/home/masteruser/restored.txt'
        },
    )
    result = control.restore_backup(
        job['job_uuid'], 'place',
        session_uuid='55555555-5555-4555-8555-555555555555',
        choice='keep_both',
    )
    assert result['destination'] == '/home/masteruser/restored.txt'


def test_run_now_remote_full_speed_is_one_run_override(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=True)
    calls = []

    async def fake_request(data, **kwargs):
        calls.append((data['job_uuid'], kwargs))
        return {'status': 'accepted'}

    monkeypatch.setattr(control, '_request_worker_run', fake_request)
    result = control.run_backup_now(job['job_uuid'], full_speed=True)
    assert result['status'] == 'accepted'
    assert calls == [(job['job_uuid'], {'full_speed': True, 'allow_large_first_backup': False})]


def test_recovery_preflight_remote_uses_read_only_worker_query(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=True)
    calls = []

    async def fake_query(data, operation, **kwargs):
        calls.append((data['job_uuid'], operation, kwargs))
        return {
            'status': 'successful',
            'snapshot_id': 'snap-1',
            'preflight': {'ready_for_offline_recovery': True},
        }

    monkeypatch.setattr(control, '_request_worker_query', fake_query)
    result = control.query_backup(
        job['job_uuid'], 'recovery_preflight', snapshot_id='snap-1'
    )
    assert result['preflight']['ready_for_offline_recovery'] is True
    assert calls == [(
        job['job_uuid'], 'recovery_preflight',
        {'snapshot_id': 'snap-1', 'directory': None},
    )]


def test_restore_stage_logs_master_lifecycle_event_after_success(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    monkeypatch.setattr(
        control, 'queue_restore_request',
        lambda operation, **kwargs: '88888888-8888-4888-8888-888888888888',
    )
    monkeypatch.setattr(
        control, 'wait_for_restore_result',
        lambda *args, **kwargs: {
            'status': 'successful',
            'session_uuid': '99999999-9999-4999-8999-999999999999',
        },
    )
    events = []
    monkeypatch.setattr(control, 'log_event', lambda *args: events.append(args) or 1)
    control.restore_backup(
        job['job_uuid'], 'stage', snapshot_id='snap-1', selection='/home/masteruser/file.txt'
    )
    assert len(events) == 1
    assert events[0][1] == 'backup.restore_started'
    assert events[0][2] == 'info'
    assert events[0][4]['snapshot_id'] == 'snap-1'


def test_restore_place_logs_completed_event_after_success(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    monkeypatch.setattr(
        control, 'queue_restore_request',
        lambda operation, **kwargs: '88888888-8888-4888-8888-888888888888',
    )
    monkeypatch.setattr(
        control, 'wait_for_restore_result',
        lambda *args, **kwargs: {
            'status': 'successful',
            'destination': '/home/masteruser/file.txt',
        },
    )
    events = []
    monkeypatch.setattr(control, 'log_event', lambda *args: events.append(args) or 1)
    control.restore_backup(
        job['job_uuid'], 'place',
        session_uuid='99999999-9999-4999-8999-999999999999',
        choice='replace',
    )
    assert len(events) == 1
    assert events[0][1] == 'backup.restore_completed'
    assert events[0][2] == 'ok'
    assert events[0][4]['destination'] == '/home/masteruser/file.txt'


def test_restore_event_failure_does_not_fail_successful_restore(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=False)
    monkeypatch.setattr(
        control, 'queue_restore_request',
        lambda operation, **kwargs: '88888888-8888-4888-8888-888888888888',
    )
    monkeypatch.setattr(
        control, 'wait_for_restore_result',
        lambda *args, **kwargs: {
            'status': 'successful',
            'session_uuid': '99999999-9999-4999-8999-999999999999',
        },
    )
    monkeypatch.setattr(
        control, 'log_event',
        lambda *args: (_ for _ in ()).throw(RuntimeError('event DB unavailable')),
    )
    result = control.restore_backup(
        job['job_uuid'], 'stage', snapshot_id='snap-1', selection='/home/masteruser/file.txt'
    )
    assert result['status'] == 'successful'


def test_run_now_remote_forwards_large_backup_confirmation(tmp_path, monkeypatch):
    job, _, _ = _db(tmp_path, monkeypatch, remote=True)
    calls = []

    async def fake_request(data, **kwargs):
        calls.append((data["job_uuid"], kwargs))
        return {"status": "accepted"}

    monkeypatch.setattr(control, "_request_worker_run", fake_request)
    result = control.run_backup_now(
        job["job_uuid"],
        allow_large_first_backup=True,
    )
    assert result["status"] == "accepted"
    assert calls == [(
        job["job_uuid"],
        {"full_speed": False, "allow_large_first_backup": True},
    )]
