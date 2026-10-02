from pathlib import Path
import uuid

import pytest

from lattice.backup.locks import BackupLockError, repository_operation_lock


def test_repository_operation_lock_blocks_conflicting_operation(tmp_path, monkeypatch):
    monkeypatch.setenv('LATTICE_BACKUP_LOCK_ROOT', str(tmp_path / 'locks'))
    job_uuid = str(uuid.uuid4())
    with repository_operation_lock(job_uuid, 'backup') as path:
        assert Path(path).is_file()
        assert Path(path).stat().st_mode & 0o777 == 0o600
        with pytest.raises(BackupLockError, match='repository is busy'):
            with repository_operation_lock(job_uuid, 'maintenance'):
                pass
    with repository_operation_lock(job_uuid, 'restore'):
        pass


def test_repository_operation_locks_are_independent_per_job(tmp_path, monkeypatch):
    monkeypatch.setenv('LATTICE_BACKUP_LOCK_ROOT', str(tmp_path / 'locks'))
    first = str(uuid.uuid4())
    second = str(uuid.uuid4())
    with repository_operation_lock(first, 'backup'):
        with repository_operation_lock(second, 'maintenance'):
            pass


def test_repository_operation_lock_rejects_unknown_operation(tmp_path, monkeypatch):
    monkeypatch.setenv('LATTICE_BACKUP_LOCK_ROOT', str(tmp_path / 'locks'))
    with pytest.raises(BackupLockError, match='operation is invalid'):
        with repository_operation_lock(str(uuid.uuid4()), 'shell'):
            pass
