from pathlib import Path
from types import SimpleNamespace
import sqlite3
import uuid

import pytest

from lattice.backup import restore_workflow
from lattice.backup.jobs import register_target
from lattice.backup.models import BackupSnapshot
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch):
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    home = tmp_path / 'home' / 'workeruser'
    home.mkdir(parents=True)
    monkeypatch.setenv(
        'LATTICE_BACKUP_RESTORE_STAGING_ROOT', str(tmp_path / 'restore-staging')
    )
    monkeypatch.setenv(
        'LATTICE_BACKUP_RESTORE_REQUEST_PATH', str(tmp_path / 'restore-request.json')
    )
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
    job_uuid = str(uuid.uuid4())
    conn = sqlite3.connect(db)
    cursor = conn.execute(
        """INSERT INTO backup_jobs(job_uuid,source_node_id,target_id,source_path)
           VALUES(?,?,?,?)""",
        (job_uuid, source, int(target['id']), str(home)),
    )
    conn.commit()
    job = {
        'id': int(cursor.lastrowid),
        'job_uuid': job_uuid,
        'source_node_id': source,
        'target_id': int(target['id']),
        'source_path': str(home),
    }
    conn.close()
    monkeypatch.setattr(
        restore_workflow, 'load_node_identity', lambda: SimpleNamespace(node_id=source)
    )
    return job, home


class FakeRepo:
    def __init__(self, home: Path, content='from backup'):
        self.home = home
        self.content = content

    def snapshots(self):
        return [
            BackupSnapshot('snap-1', '2026-09-03T02:00:00Z', 'worker-node', (str(self.home),))
        ]

    def restore_to_staging(self, snapshot_id, staging, *, include=None):
        assert snapshot_id == 'snap-1'
        selected = Path(str(include))
        destination = Path(staging).joinpath(*selected.parts[1:])
        destination.parent.mkdir(parents=True, exist_ok=True)
        if selected.suffix:
            destination.write_text(self.content)
        else:
            destination.mkdir(parents=True, exist_ok=True)
            (destination / 'inside.txt').write_text(self.content)
        return Path(staging)


def _stage(tmp_path, monkeypatch, *, conflict=True):
    job, home = _setup(tmp_path, monkeypatch)
    selected = home / 'notes.txt'
    if conflict:
        selected.write_text('current')
    monkeypatch.setattr(
        restore_workflow, '_repository_candidates', lambda job_row: [FakeRepo(home)]
    )
    staged = restore_workflow.stage_restore(job['job_uuid'], 'snap-1', str(selected))
    return job, home, selected, staged


def test_stage_restore_never_writes_home_and_reports_conflict(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    assert selected.read_text() == 'current'
    assert staged['status'] == 'staged'
    assert staged['conflict'] is True
    assert staged['selection'] == str(selected)
    assert staged['type'] == 'file'


def test_keep_both_preserves_existing_original(tmp_path, monkeypatch):
    _, home, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    result = restore_workflow.place_restore(staged['session_uuid'], 'keep_both')
    restored = Path(result['destination'])
    assert selected.read_text() == 'current'
    assert restored.parent == home
    assert restored.read_text() == 'from backup'
    assert restored != selected


def test_keep_both_refuses_destination_that_appears_during_copy(tmp_path, monkeypatch):
    _, home, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    raced_destination = home / "raced-restore.txt"
    monkeypatch.setattr(
        restore_workflow,
        "_keep_both_destination",
        lambda original: raced_destination,
    )
    real_copy = restore_workflow._copy_archive

    def copy_then_race(source, temporary):
        real_copy(source, temporary)
        raced_destination.write_text("new user data")

    monkeypatch.setattr(restore_workflow, "_copy_archive", copy_then_race)

    with pytest.raises(
        restore_workflow.BackupRestoreWorkflowError,
        match="nothing was overwritten",
    ):
        restore_workflow.place_restore(staged["session_uuid"], "keep_both")

    assert selected.read_text() == "current"
    assert raced_destination.read_text() == "new user data"
    assert not list(home.glob(".lattice-restore-new-*"))


def test_replace_places_backup_at_original_location(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    result = restore_workflow.place_restore(staged['session_uuid'], 'replace')
    assert result['destination'] == str(selected)
    assert selected.read_text() == 'from backup'
    assert not list(selected.parent.glob('.lattice-restore-replaced-*'))


def test_replace_rolls_original_back_when_copy_fails(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)

    def fail_copy(source, destination):
        raise restore_workflow.BackupRestoreWorkflowError('simulated copy failure')

    monkeypatch.setattr(restore_workflow, '_copy_archive', fail_copy)
    with pytest.raises(restore_workflow.BackupRestoreWorkflowError, match='simulated'):
        restore_workflow.place_restore(staged['session_uuid'], 'replace')
    assert selected.read_text() == 'current'
    assert not list(selected.parent.glob('.lattice-restore-replaced-*'))

def test_replace_rolls_original_back_after_partial_copy(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)

    def partial_copy(source, destination):
        Path(destination).write_text('PARTIAL')
        raise restore_workflow.BackupRestoreWorkflowError('simulated partial copy failure')

    monkeypatch.setattr(restore_workflow, '_copy_archive', partial_copy)
    with pytest.raises(restore_workflow.BackupRestoreWorkflowError, match='partial copy'):
        restore_workflow.place_restore(staged['session_uuid'], 'replace')
    assert selected.read_text() == 'current'
    assert not list(selected.parent.glob('.lattice-restore-new-*'))
    assert not list(selected.parent.glob('.lattice-restore-replaced-*'))



def test_replace_retry_recovers_interrupted_partial_copy(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    session_uuid = staged["session_uuid"]
    rollback = selected.parent / f".lattice-restore-replaced-{session_uuid}"
    temporary = selected.parent / f".lattice-restore-new-{session_uuid}"
    selected.replace(rollback)
    temporary.write_text("PARTIAL")

    result = restore_workflow.place_restore(session_uuid, "replace")

    assert result["status"] == "placed"
    assert selected.read_text() == "from backup"
    assert not rollback.exists()
    assert not temporary.exists()


def test_replace_retry_refuses_ambiguous_original_and_replacement(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    session_uuid = staged["session_uuid"]
    rollback = selected.parent / f".lattice-restore-replaced-{session_uuid}"
    selected.replace(rollback)
    selected.write_text("possibly-complete-restored-data")

    with pytest.raises(
        restore_workflow.BackupRestoreWorkflowError,
        match="refusing to choose",
    ):
        restore_workflow.place_restore(session_uuid, "replace")

    assert rollback.read_text() == "current"
    assert selected.read_text() == "possibly-complete-restored-data"

def test_elsewhere_must_stay_inside_home_and_not_exist(tmp_path, monkeypatch):
    _, home, _, staged = _stage(tmp_path, monkeypatch, conflict=False)
    outside = tmp_path / 'outside.txt'
    with pytest.raises(restore_workflow.BackupRestoreWorkflowError, match='outside the protected Home'):
        restore_workflow.place_restore(
            staged['session_uuid'], 'elsewhere', elsewhere=str(outside)
        )
    destination = home / 'Restored' / 'notes.txt'
    result = restore_workflow.place_restore(
        staged['session_uuid'], 'elsewhere', elsewhere=str(destination)
    )
    assert Path(result['destination']).read_text() == 'from backup'




def test_place_restore_preserves_staging_if_terminal_db_update_fails(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    session = restore_workflow._session(staged["session_uuid"])
    staging = Path(session["staging_path"])
    real_get_db = restore_workflow.get_db_connection

    class FailingCommitConnection:
        def __init__(self, inner):
            self.inner = inner

        def execute(self, *args, **kwargs):
            return self.inner.execute(*args, **kwargs)

        def commit(self):
            raise sqlite3.OperationalError("simulated durable state failure")

        def close(self):
            self.inner.close()

    monkeypatch.setattr(
        restore_workflow,
        "get_db_connection",
        lambda: FailingCommitConnection(real_get_db()),
    )
    with pytest.raises(sqlite3.OperationalError, match="simulated"):
        restore_workflow.place_restore(staged["session_uuid"], "replace")
    assert selected.read_text() == "from backup"
    rollback = selected.parent / f".lattice-restore-replaced-{staged['session_uuid']}"
    assert rollback.read_text() == "current"
    assert staging.exists()

def test_cancel_removes_staging_without_touching_home(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    session = restore_workflow._session(staged['session_uuid'])
    staging = Path(session['staging_path'])
    assert staging.exists()
    result = restore_workflow.cancel_restore(staged['session_uuid'])
    assert result['status'] == 'cancelled'
    assert not staging.exists()
    assert selected.read_text() == 'current'

def test_cancel_refuses_database_staging_path_outside_root(tmp_path, monkeypatch):
    _, _, selected, staged = _stage(tmp_path, monkeypatch, conflict=True)
    outside = tmp_path / 'outside-sentinel'
    outside.mkdir()
    (outside / 'keep.txt').write_text('KEEP')
    conn = sqlite3.connect(tmp_path / 'state.sqlite')
    conn.execute(
        'UPDATE backup_restore_sessions SET staging_path=? WHERE session_uuid=?',
        (str(outside), staged['session_uuid']),
    )
    conn.commit(); conn.close()

    with pytest.raises(restore_workflow.BackupRestoreWorkflowError, match='protected session directory'):
        restore_workflow.cancel_restore(staged['session_uuid'])
    assert (outside / 'keep.txt').read_text() == 'KEEP'
    assert selected.read_text() == 'current'


def test_restore_selection_rejects_path_outside_home(tmp_path, monkeypatch):
    job, home = _setup(tmp_path, monkeypatch)
    monkeypatch.setattr(
        restore_workflow, '_repository_candidates', lambda job_row: [FakeRepo(home)]
    )
    with pytest.raises(restore_workflow.BackupRestoreWorkflowError, match='outside the protected Home'):
        restore_workflow.stage_restore(job['job_uuid'], 'snap-1', str(tmp_path / 'etc' / 'passwd'))


def test_failed_first_restore_route_is_cleared_before_retry(tmp_path, monkeypatch):
    job, home = _setup(tmp_path, monkeypatch)
    selected = home / 'notes.txt'

    class PartialFailureRepo(FakeRepo):
        def restore_to_staging(self, snapshot_id, staging, *, include=None):
            partial = Path(staging) / 'partial-garbage.txt'
            partial.write_text('partial')
            raise restore_workflow.ResticError('first route failed')

    class CleanSecondRepo(FakeRepo):
        def restore_to_staging(self, snapshot_id, staging, *, include=None):
            assert not (Path(staging) / 'partial-garbage.txt').exists()
            return super().restore_to_staging(snapshot_id, staging, include=include)

    monkeypatch.setattr(
        restore_workflow,
        '_repository_candidates',
        lambda job_row: [PartialFailureRepo(home), CleanSecondRepo(home)],
    )
    staged = restore_workflow.stage_restore(job['job_uuid'], 'snap-1', str(selected))
    assert staged['status'] == 'staged'
    session = restore_workflow._session(staged['session_uuid'])
    assert not (Path(session['staging_path']) / 'partial-garbage.txt').exists()


def test_restore_staging_cleanup_preserves_active_staged_session(tmp_path, monkeypatch):
    _, _, _, staged = _stage(tmp_path, monkeypatch, conflict=False)
    session = restore_workflow._session(staged['session_uuid'])
    staging = Path(session['staging_path'])
    result = restore_workflow.cleanup_restore_staging(now_timestamp=10_000_000)
    assert result['preserved_staged'] == 1
    assert staging.exists()


def test_restore_staging_cleanup_removes_terminal_session_leftovers(tmp_path, monkeypatch):
    _, _, _, staged = _stage(tmp_path, monkeypatch, conflict=False)
    session = restore_workflow._session(staged['session_uuid'])
    staging = Path(session['staging_path'])
    db = Path(__import__('os').environ['LATTICE_DB_PATH'])
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE backup_restore_sessions SET state='cancelled' WHERE session_uuid=?",
        (staged['session_uuid'],),
    )
    conn.commit(); conn.close()
    result = restore_workflow.cleanup_restore_staging(now_timestamp=10_000_000)
    assert result['removed_terminal'] == 1
    assert not staging.exists()


def test_restore_staging_cleanup_removes_only_old_uuid_orphans(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    root = Path(__import__('os').environ['LATTICE_BACKUP_RESTORE_STAGING_ROOT'])
    root.mkdir(parents=True, exist_ok=True)
    old = root / str(uuid.uuid4())
    recent = root / str(uuid.uuid4())
    unrelated = root / 'do-not-touch'
    old.mkdir(); recent.mkdir(); unrelated.mkdir()
    __import__('os').utime(old, (1000, 1000))
    __import__('os').utime(recent, (9_999_000, 9_999_000))
    result = restore_workflow.cleanup_restore_staging(
        orphan_age_seconds=3600,
        now_timestamp=10_000_000,
    )
    assert result['removed_orphan'] == 1
    assert not old.exists()
    assert recent.exists()
    assert unrelated.exists()


def test_restore_staging_cleanup_does_not_remove_orphan_during_active_request(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    root = Path(__import__('os').environ['LATTICE_BACKUP_RESTORE_STAGING_ROOT'])
    root.mkdir(parents=True, exist_ok=True)
    orphan = root / str(uuid.uuid4())
    orphan.mkdir()
    __import__('os').utime(orphan, (1000, 1000))
    request = tmp_path / 'restore-request.json'
    request.write_text('{}')
    monkeypatch.setenv('LATTICE_BACKUP_RESTORE_REQUEST_PATH', str(request))
    result = restore_workflow.cleanup_restore_staging(
        orphan_age_seconds=3600,
        now_timestamp=10_000_000,
    )
    assert result['removed_orphan'] == 0
    assert orphan.exists()
