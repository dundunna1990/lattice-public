from pathlib import Path

from lattice.backup.models import BackupSnapshotStats
from lattice.backup import recovery


def _job():
    return {
        'source_path': '/home/workeruser',
        'main_user': 'workeruser',
        'main_uid': 1000,
        'main_gid': 1000,
    }


def _account_ok(_name):
    return {'present': True, 'uid': 1000, 'gid': 1000}


def _home_ok(_path):
    return {
        'exists': True,
        'is_directory': True,
        'is_symlink': False,
        'uid': 1000,
        'gid': 1000,
    }


def test_full_home_preflight_same_filesystem_requires_double_restore_space(tmp_path):
    def fs(_path):
        return {'anchor': '/', 'device': 42, 'total_bytes': 10_000, 'free_bytes': 8_000}

    result = recovery.full_home_recovery_preflight(
        _job(),
        BackupSnapshotStats(total_size=3_000, total_file_count=20),
        staging_root=tmp_path / 'staging',
        snapshot_completed=True,
        filesystem_inspector=fs,
        account_inspector=_account_ok,
        home_inspector=_home_ok,
    )
    assert result['staging_and_home_same_filesystem'] is True
    assert result['required_staging_free_bytes'] == 6_000
    assert result['space_ok'] is True
    assert result['ready_for_offline_recovery'] is True
    assert result['live_replacement_allowed'] is False
    assert result['requires_offline_recovery'] is True
    assert any('live wholesale replacement' in item for item in result['warnings'])


def test_full_home_preflight_blocks_insufficient_same_filesystem_space(tmp_path):
    def fs(_path):
        return {'anchor': '/', 'device': 42, 'total_bytes': 10_000, 'free_bytes': 4_000}

    result = recovery.full_home_recovery_preflight(
        _job(),
        BackupSnapshotStats(total_size=3_000, total_file_count=20),
        staging_root=tmp_path / 'staging',
        snapshot_completed=True,
        filesystem_inspector=fs,
        account_inspector=_account_ok,
        home_inspector=_home_ok,
    )
    assert result['space_ok'] is False
    assert result['ready_for_offline_recovery'] is False
    assert any('not enough free space' in item for item in result['blockers'])


def test_full_home_preflight_separate_filesystems_checks_each_once(tmp_path):
    def fs(path):
        device = 1 if 'staging' in str(path) else 2
        return {'anchor': '/', 'device': device, 'total_bytes': 10_000, 'free_bytes': 5_000}

    result = recovery.full_home_recovery_preflight(
        _job(),
        BackupSnapshotStats(total_size=4_000, total_file_count=50),
        staging_root=tmp_path / 'staging',
        snapshot_completed=True,
        filesystem_inspector=fs,
        account_inspector=_account_ok,
        home_inspector=_home_ok,
    )
    assert result['staging_and_home_same_filesystem'] is False
    assert result['required_staging_free_bytes'] == 4_000
    assert result['required_home_free_bytes'] == 4_000
    assert result['space_ok'] is True


def test_full_home_preflight_blocks_account_identity_mismatch(tmp_path):
    def fs(_path):
        return {'anchor': '/', 'device': 42, 'total_bytes': 100_000, 'free_bytes': 99_000}

    result = recovery.full_home_recovery_preflight(
        _job(),
        BackupSnapshotStats(total_size=1_000, total_file_count=10),
        staging_root=tmp_path / 'staging',
        snapshot_completed=True,
        filesystem_inspector=fs,
        account_inspector=lambda _name: {'present': True, 'uid': 2000, 'gid': 2000},
        home_inspector=_home_ok,
    )
    assert result['account_matches_expected'] is False
    assert result['ready_for_offline_recovery'] is False
    assert any('UID/GID' in item for item in result['blockers'])


def test_full_home_preflight_rejects_non_home_source(tmp_path):
    bad = dict(_job())
    bad['source_path'] = '/srv/data'
    try:
        recovery.full_home_recovery_preflight(
            bad,
            BackupSnapshotStats(total_size=1, total_file_count=1),
            staging_root=tmp_path / 'staging',
            snapshot_completed=True,
            filesystem_inspector=lambda _p: {'device': 1, 'total_bytes': 10, 'free_bytes': 10},
            account_inspector=_account_ok,
            home_inspector=_home_ok,
        )
    except recovery.BackupRecoveryError as exc:
        assert 'exact /home/<user>' in str(exc)
    else:
        raise AssertionError('unsafe source was accepted')


def test_full_home_preflight_blocks_snapshot_not_verified(tmp_path):
    def fs(_path):
        return {'anchor': '/', 'device': 42, 'total_bytes': 100_000, 'free_bytes': 99_000}

    result = recovery.full_home_recovery_preflight(
        _job(),
        BackupSnapshotStats(total_size=1_000, total_file_count=10),
        staging_root=tmp_path / 'staging',
        snapshot_completed=False,
        filesystem_inspector=fs,
        account_inspector=_account_ok,
        home_inspector=_home_ok,
    )
    assert result['snapshot_completed'] is False
    assert result['ready_for_offline_recovery'] is False
    assert any('not recorded as a completed Lattice backup' in item for item in result['blockers'])
