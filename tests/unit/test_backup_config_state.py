from datetime import datetime, timezone
from types import SimpleNamespace
import sqlite3
import uuid

import pytest

from lattice.backup import config_state
from lattice.backup.config_state import (
    BackupConfigStateError,
    apply_signed_config,
    applied_config_generation,
    runtime_policy,
    sign_config,
    verify_config,
)
from lattice.backup.scheduler import due_jobs
from lattice.core.migrations import run_migrations
from lattice.file_access.keys import ensure_fleet_signing_identity


def _node(conn, node_id, hostname, user):
    conn.execute(
        """INSERT INTO fleet_nodes(
               node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (node_id, hostname, 'worker', user, 1000, 1000),
    )


def _payload(fleet_id, source, target, *, generation=1, paused=False):
    target_uuid = str(uuid.uuid4())
    job_uuid = str(uuid.uuid4())
    return {
        'schema_version': 1,
        'fleet_id': fleet_id,
        'generation': generation,
        'policy': {
            'schedule_hour': 2,
            'retention_daily': 30,
            'retention_weekly': 26,
            'retention_monthly': 12,
            'free_space_reserve_percent': 20,
            'deep_verification_days': 7,
            'persistent_alert_seconds': 86400,
            'bandwidth_limit_kib': 0,
        },
        'targets': [{
            'target_uuid': target_uuid,
            'friendly_name': 'Backup Drive',
            'host_node_id': target,
            'filesystem_uuid': 'physical-drive-uuid',
            'repository_relative_path': 'LatticeBackups',
            'repository_root': '/old/mount/LatticeBackups',
        }],
        'jobs': [{
            'job_uuid': job_uuid,
            'source_node_id': source,
            'target_uuid': target_uuid,
            'source_path': '/home/workeruser',
            'paused': paused,
            'pause_reason': 'Maintenance' if paused else None,
        }],
    }


def _worker_db(tmp_path, monkeypatch, source, target):
    db = tmp_path / 'worker.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    _node(conn, source, 'worker-node', 'workeruser')
    _node(conn, target, 'backup-node', 'backupuser')
    conn.commit(); conn.close()
    return db


def test_signed_config_applies_source_owned_job_and_policy(tmp_path, monkeypatch):
    source, target = str(uuid.uuid4()), str(uuid.uuid4())
    fleet_id = str(uuid.uuid4())
    _worker_db(tmp_path, monkeypatch, source, target)
    signer = ensure_fleet_signing_identity(tmp_path / 'signer')
    payload = _payload(fleet_id, source, target)
    signature = sign_config(payload, signer.private_key)
    monkeypatch.setattr(
        config_state,
        'load_pinned_fleet_bootstrap',
        lambda: {
            'fleet_id': fleet_id,
            'fleet_signing_public_key': signer.public_key_text,
        },
    )
    monkeypatch.setattr(
        config_state,
        'load_node_identity',
        lambda: SimpleNamespace(node_id=source),
    )

    assert verify_config(payload, signature, signer.public_key_text)
    assert apply_signed_config(payload, signature) == 1
    assert applied_config_generation() == 1
    assert runtime_policy()['free_space_reserve_percent'] == 20

    conn = sqlite3.connect(tmp_path / 'worker.sqlite')
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """SELECT bj.job_uuid,bj.source_path,bj.enabled,bj.paused,
                  bt.target_uuid,bt.host_node_id,bt.target_type,bt.filesystem_uuid,
                  bt.repository_relative_path
           FROM backup_jobs bj JOIN backup_targets bt ON bt.id=bj.target_id"""
    ).fetchone()
    conn.close()
    assert row['job_uuid'] == payload['jobs'][0]['job_uuid']
    assert row['source_path'] == '/home/workeruser'
    assert row['enabled'] == 1
    assert row['paused'] == 0
    assert row['host_node_id'] == target
    assert row['target_type'] == 'remote_storage'
    assert row['filesystem_uuid'] == 'physical-drive-uuid'
    assert row['repository_relative_path'] == 'LatticeBackups'

    # No master lookup is needed to decide the job is due.
    jobs = due_jobs(
        now=datetime(2026, 9, 3, 12, tzinfo=timezone.utc),
        source_node_id=source,
    )
    assert [item['job_uuid'] for item in jobs] == [payload['jobs'][0]['job_uuid']]


def test_signed_config_materializes_missing_worker_fleet_references(tmp_path, monkeypatch):
    source, target = str(uuid.uuid4()), str(uuid.uuid4())
    fleet_id = str(uuid.uuid4())
    db = tmp_path / 'worker-empty.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    conn.commit()
    conn.close()

    signer = ensure_fleet_signing_identity(tmp_path / 'signer-empty-worker')
    payload = _payload(fleet_id, source, target)
    signature = sign_config(payload, signer.private_key)
    manifest = {
        'generation': 1,
        'members': [
            {
                'node_id': source,
                'hostname': 'worker-node',
                'role': 'worker',
                'main_user': 'workeruser',
            },
            {
                'node_id': target,
                'hostname': 'backup-node',
                'role': 'worker',
                'main_user': 'backupuser',
            },
        ],
    }
    monkeypatch.setattr(
        config_state,
        'load_pinned_fleet_bootstrap',
        lambda: {
            'fleet_id': fleet_id,
            'fleet_signing_public_key': signer.public_key_text,
        },
    )
    monkeypatch.setattr(
        config_state,
        'get_cached_signed_manifest',
        lambda: (manifest, 'already-verified-signature'),
    )
    monkeypatch.setattr(
        config_state,
        'load_node_identity',
        lambda: SimpleNamespace(
            node_id=source,
            main_uid=1000,
            main_gid=1000,
        ),
    )

    assert apply_signed_config(payload, signature) == 1

    conn = sqlite3.connect(db)
    assert conn.execute('SELECT COUNT(*) FROM fleet_nodes').fetchone()[0] == 2
    assert conn.execute('SELECT COUNT(*) FROM backup_targets').fetchone()[0] == 1
    assert conn.execute('SELECT COUNT(*) FROM backup_jobs').fetchone()[0] == 1
    local_uid = conn.execute(
        'SELECT main_uid FROM fleet_nodes WHERE node_id=?', (source,)
    ).fetchone()[0]
    remote_uid = conn.execute(
        'SELECT main_uid FROM fleet_nodes WHERE node_id=?', (target,)
    ).fetchone()[0]
    conn.close()
    assert local_uid == 1000
    assert remote_uid == -1


def test_config_removal_disables_local_job_without_deleting_history(tmp_path, monkeypatch):
    source, target = str(uuid.uuid4()), str(uuid.uuid4())
    fleet_id = str(uuid.uuid4())
    _worker_db(tmp_path, monkeypatch, source, target)
    signer = ensure_fleet_signing_identity(tmp_path / 'signer')
    first = _payload(fleet_id, source, target)
    monkeypatch.setattr(
        config_state, 'load_pinned_fleet_bootstrap',
        lambda: {'fleet_id': fleet_id, 'fleet_signing_public_key': signer.public_key_text},
    )
    monkeypatch.setattr(
        config_state, 'load_node_identity', lambda: SimpleNamespace(node_id=source)
    )
    apply_signed_config(first, sign_config(first, signer.private_key))

    conn = sqlite3.connect(tmp_path / 'worker.sqlite')
    job_id = conn.execute('SELECT id FROM backup_jobs').fetchone()[0]
    conn.execute(
        "INSERT INTO backup_runs(job_id,started_at,finished_at,result) VALUES(?,?,?,'successful')",
        (job_id, '2026-09-02T02:00:00+00:00', '2026-09-02T02:05:00+00:00'),
    )
    conn.commit(); conn.close()

    second = dict(first)
    second['generation'] = 2
    second['jobs'] = []
    apply_signed_config(second, sign_config(second, signer.private_key))
    conn = sqlite3.connect(tmp_path / 'worker.sqlite')
    enabled = conn.execute('SELECT enabled FROM backup_jobs WHERE id=?', (job_id,)).fetchone()[0]
    history = conn.execute('SELECT COUNT(*) FROM backup_runs WHERE job_id=?', (job_id,)).fetchone()[0]
    conn.close()
    assert enabled == 0
    assert history == 1


def test_config_rollback_is_rejected(tmp_path, monkeypatch):
    source, target = str(uuid.uuid4()), str(uuid.uuid4())
    fleet_id = str(uuid.uuid4())
    _worker_db(tmp_path, monkeypatch, source, target)
    signer = ensure_fleet_signing_identity(tmp_path / 'signer')
    newer = _payload(fleet_id, source, target, generation=2)
    monkeypatch.setattr(
        config_state, 'load_pinned_fleet_bootstrap',
        lambda: {'fleet_id': fleet_id, 'fleet_signing_public_key': signer.public_key_text},
    )
    monkeypatch.setattr(
        config_state, 'load_node_identity', lambda: SimpleNamespace(node_id=source)
    )
    apply_signed_config(newer, sign_config(newer, signer.private_key))
    older = dict(newer); older['generation'] = 1
    with pytest.raises(BackupConfigStateError, match='roll back'):
        apply_signed_config(older, sign_config(older, signer.private_key))


def test_target_host_replica_labels_its_physical_target_local(tmp_path, monkeypatch):
    source, target = str(uuid.uuid4()), str(uuid.uuid4())
    fleet_id = str(uuid.uuid4())
    _worker_db(tmp_path, monkeypatch, source, target)
    signer = ensure_fleet_signing_identity(tmp_path / 'signer-local-target')
    payload = _payload(fleet_id, source, target)
    monkeypatch.setattr(
        config_state, 'load_pinned_fleet_bootstrap',
        lambda: {'fleet_id': fleet_id, 'fleet_signing_public_key': signer.public_key_text},
    )
    monkeypatch.setattr(
        config_state, 'load_node_identity', lambda: SimpleNamespace(node_id=target)
    )
    apply_signed_config(payload, sign_config(payload, signer.private_key))
    conn = sqlite3.connect(tmp_path / 'worker.sqlite')
    row = conn.execute(
        'SELECT target_type FROM backup_targets WHERE target_uuid=?',
        (payload['targets'][0]['target_uuid'],),
    ).fetchone()
    conn.close()
    assert row[0] == 'local_storage'
