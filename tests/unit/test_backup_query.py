from pathlib import Path
from types import SimpleNamespace
import json
import sqlite3
import uuid

import pytest

from lattice.backup import query
from lattice.backup.jobs import create_job, register_target
from lattice.backup.models import BackupEntry, BackupSnapshot
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch, *, paused=False):
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    monkeypatch.setenv('LATTICE_BACKUP_QUERY_REQUEST_PATH', str(tmp_path / 'query-request.json'))
    monkeypatch.setenv('LATTICE_BACKUP_QUERY_RESULT_PATH', str(tmp_path / 'query-result.json'))
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
    if paused:
        conn = sqlite3.connect(db)
        conn.execute(
            "UPDATE backup_jobs SET paused=1,pause_reason='Maintenance' WHERE id=?",
            (job['id'],),
        )
        conn.commit(); conn.close()
    monkeypatch.setattr(query, 'load_node_identity', lambda: SimpleNamespace(node_id=source))
    return job, source


class Repo:
    def snapshots(self):
        return [
            BackupSnapshot('good', '2026-09-03T02:00:00Z', 'worker-node', ('/home/workeruser',)),
            BackupSnapshot('other', '2026-09-02T02:00:00Z', 'other', ('/home/other',)),
        ]

    def list_snapshot_directory(self, snapshot_id, directory, *, limit=500):
        assert snapshot_id == 'good'
        assert directory == '/home/workeruser'
        assert limit == 500
        return [
            BackupEntry('/home/workeruser/Documents', 'Documents', 'dir', 0, None),
            BackupEntry('/home/workeruser/notes.txt', 'notes.txt', 'file', 42, '2026-09-03T01:00:00Z'),
        ]


def test_query_queue_allows_browse_while_job_paused(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch, paused=True)
    request_id = query.queue_backup_query(job['job_uuid'], 'snapshots')
    payload = json.loads((tmp_path / 'query-request.json').read_text())
    assert payload['request_id'] == request_id
    assert payload['operation'] == 'snapshots'


def test_query_queue_rejects_directory_outside_home(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)
    with pytest.raises(query.BackupQueryError, match='outside the protected Home'):
        query.queue_backup_query(
            job['job_uuid'], 'directory', snapshot_id='good', directory='/etc'
        )


def test_snapshot_query_filters_to_job_source(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(query, '_repository_candidates', lambda _job: [Repo()])
    result = query._query_repository(query._job(job['job_uuid']), 'snapshots', None, None)
    assert result['source_root'] == '/home/workeruser'
    assert [item['snapshot_id'] for item in result['snapshots']] == ['good']


def test_directory_query_returns_bounded_safe_metadata(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(query, '_repository_candidates', lambda _job: [Repo()])
    result = query._query_repository(
        query._job(job['job_uuid']), 'directory', 'good', '/home/workeruser'
    )
    assert result['snapshot_id'] == 'good'
    assert result['entries'] == [
        {
            'path': '/home/workeruser/Documents', 'name': 'Documents',
            'type': 'dir', 'size': 0, 'modified_at': None,
        },
        {
            'path': '/home/workeruser/notes.txt', 'name': 'notes.txt',
            'type': 'file', 'size': 42, 'modified_at': '2026-09-03T01:00:00Z',
        },
    ]


def test_recovery_preflight_query_requires_snapshot_and_returns_read_only_report(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)

    class RecoveryRepo(Repo):
        def snapshot_restore_stats(self, snapshot_id):
            assert snapshot_id == 'good'
            from lattice.backup.models import BackupSnapshotStats
            return BackupSnapshotStats(total_size=1234, total_file_count=56)

    monkeypatch.setattr(query, '_repository_candidates', lambda _job: [RecoveryRepo()])
    monkeypatch.setattr(query, '_completed_snapshot_ids', lambda _job_id: {'good'})
    seen = []
    monkeypatch.setattr(
        query,
        'full_home_recovery_preflight',
        lambda job_row, stats, staging_root, snapshot_completed: seen.append((job_row['job_uuid'], stats.total_size, str(staging_root), snapshot_completed)) or {
            'ready_for_offline_recovery': snapshot_completed,
            'live_replacement_allowed': False,
        },
    )
    result = query._query_repository(
        query._job(job['job_uuid']), 'recovery_preflight', 'good', None
    )
    assert result['snapshot_id'] == 'good'
    assert result['preflight']['ready_for_offline_recovery'] is True
    assert result['preflight']['live_replacement_allowed'] is False
    assert seen[0][0] == job['job_uuid']
    assert seen[0][1] == 1234


def test_recovery_preflight_queue_requires_snapshot_id(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)
    with pytest.raises(query.BackupQueryError, match='Snapshot ID is required'):
        query.queue_backup_query(job['job_uuid'], 'recovery_preflight')


def test_snapshot_list_marks_verified_and_unknown_health(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)

    class SnapshotHealthRepo(Repo):
        def snapshots(self):
            return [
                BackupSnapshot('good', '2026-09-03T02:00:00Z', 'worker-node', ('/home/workeruser',)),
                BackupSnapshot('legacy', '2026-09-02T02:00:00Z', 'worker-node', ('/home/workeruser',)),
                BackupSnapshot('other', '2026-09-01T02:00:00Z', 'other', ('/home/other',)),
            ]

    monkeypatch.setattr(query, '_repository_candidates', lambda _job: [SnapshotHealthRepo()])
    monkeypatch.setattr(query, '_completed_snapshot_ids', lambda _job_id: {'good'})
    result = query._query_repository(
        query._job(job['job_uuid']), 'snapshots', None, None
    )
    health = {item['snapshot_id']: item['health'] for item in result['snapshots']}
    assert health == {'good': 'completed', 'legacy': 'unknown'}


def test_recovery_preflight_passes_unverified_state_to_safety_check(tmp_path, monkeypatch):
    job, _ = _setup(tmp_path, monkeypatch)

    class RecoveryRepo(Repo):
        def snapshot_restore_stats(self, snapshot_id):
            from lattice.backup.models import BackupSnapshotStats
            return BackupSnapshotStats(total_size=100, total_file_count=2)

    monkeypatch.setattr(query, '_repository_candidates', lambda _job: [RecoveryRepo()])
    monkeypatch.setattr(query, '_completed_snapshot_ids', lambda _job_id: set())
    seen = []
    monkeypatch.setattr(
        query,
        'full_home_recovery_preflight',
        lambda job_row, stats, staging_root, snapshot_completed: seen.append(snapshot_completed) or {
            'ready_for_offline_recovery': False,
            'snapshot_completed': snapshot_completed,
        },
    )
    result = query._query_repository(
        query._job(job['job_uuid']), 'recovery_preflight', 'good', None
    )
    assert seen == [False]
    assert result['preflight']['ready_for_offline_recovery'] is False
