from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import sqlite3
import uuid

import pytest

from lattice.backup import maintenance
from lattice.backup.credentials import create_password_file
from lattice.backup.jobs import create_job, register_target
from lattice.backup.models import BackupEntry, BackupSnapshot, MountIdentity
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch):
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (node, 'master-node', 'master', 'masteruser', 1000, 1000),
    )
    conn.commit(); conn.close()
    mount = tmp_path / 'drive'; mount.mkdir()
    repo_root = mount / 'LatticeBackups'; repo_root.mkdir()
    target = register_target(
        friendly_name='Backup Drive', host_node_id=node,
        filesystem_uuid='disk-uuid', repository_root=str(repo_root),
        target_type='local_storage',
    )
    job = create_job(
        source_node_id=node, target_id=target['id'], source_path='/home/masteruser'
    )
    monkeypatch.setattr(
        maintenance, 'load_node_identity', lambda: SimpleNamespace(node_id=node)
    )
    creds = tmp_path / 'creds'
    create_password_file(creds / f"{job['job_uuid']}.password")
    return job, mount, repo_root


class Repo:
    def __init__(self, repository, password_file):
        self.repository = repository
        self.password_file = password_file
        self.retention = None
        self.checks = []

    def apply_retention(self, **kwargs):
        self.retention = kwargs

    def snapshots(self):
        return [BackupSnapshot('snap', '2026-09-03T02:00:00Z', 'master-node', ('/home/masteruser',))]

    def check(self, *, read_data_subset=None):
        self.checks.append(read_data_subset)


def test_normal_retention_uses_agreed_policy(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    data = maintenance._job(job['id'])
    repo = Repo('/repo', '/password')
    maintenance.apply_normal_retention(repo, data)
    assert repo.retention == {
        'keep_daily': 30,
        'keep_weekly': 26,
        'keep_monthly': 12,
        'hostname': 'master-node',
        'prune': True,
    }


def test_retention_refuses_result_with_no_protected_snapshot(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    data = maintenance._job(job['id'])
    repo = Repo('/repo', '/password')
    repo.snapshots = lambda: []
    with pytest.raises(maintenance.BackupMaintenanceError, match='no protected snapshot'):
        maintenance.apply_normal_retention(repo, data)


def test_reserve_below_threshold_uses_only_normal_retention_then_rechecks(tmp_path, monkeypatch):
    job, mount, repo_root = _setup(tmp_path, monkeypatch)
    (repo_root / job['source_node_id']).mkdir()
    states = iter([
        maintenance.CapacityState(1000, 100, 20),
        maintenance.CapacityState(1000, 250, 20),
    ])
    repos = []
    class R(Repo):
        def __init__(self, repository, password_file):
            super().__init__(repository, password_file); repos.append(self)
    result = maintenance.ensure_local_free_space(
        job['id'], credential_root=tmp_path / 'creds', repository_factory=R,
        target_resolver=lambda fs_uuid, relative: (repo_root, MountIdentity(mount, fs_uuid, '/dev/test', 'ext4', frozenset({'rw'}))),
        capacity_reader=lambda path, reserve_percent: next(states),
    )
    assert result.reserve_satisfied
    assert len(repos) == 1
    assert repos[0].retention['keep_daily'] == 30


def test_reserve_still_low_fails_instead_of_extra_deletion(tmp_path, monkeypatch):
    job, mount, repo_root = _setup(tmp_path, monkeypatch)
    (repo_root / job['source_node_id']).mkdir()
    states = iter([
        maintenance.CapacityState(1000, 100, 20),
        maintenance.CapacityState(1000, 150, 20),
    ])
    with pytest.raises(maintenance.BackupMaintenanceError, match='remains below'):
        maintenance.ensure_local_free_space(
            job['id'], credential_root=tmp_path / 'creds', repository_factory=Repo,
            target_resolver=lambda fs_uuid, relative: (repo_root, MountIdentity(mount, fs_uuid, '/dev/test', 'ext4', frozenset({'rw'}))),
            capacity_reader=lambda path, reserve_percent: next(states),
        )


def test_deep_verification_due_uses_durable_interval(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    now = datetime(2026, 9, 3, 12, tzinfo=timezone.utc)
    assert maintenance.deep_verification_due(job['id'], now=now)
    conn = sqlite3.connect(Path(__import__('os').environ['LATTICE_DB_PATH']))
    conn.execute(
        "INSERT INTO backup_maintenance_state(job_id,last_deep_verification_at,last_result) VALUES(?,?, 'healthy')",
        (job['id'], (now - timedelta(days=2)).isoformat()),
    )
    conn.commit(); conn.close()
    assert not maintenance.deep_verification_due(job['id'], now=now)
    assert maintenance.deep_verification_due(job['id'], now=now + timedelta(days=8))


class RestoreProbeRepo(Repo):
    payload = b"verified-backup-data"

    def list_snapshot_directory(self, snapshot_id, directory, limit=500):
        return [
            BackupEntry(
                path="/home/masteruser/.bashrc",
                name=".bashrc",
                entry_type="file",
                size=len(self.payload),
                modified_at="2026-09-03T02:00:00Z",
            )
        ]

    def restore_to_staging(self, snapshot_id, staging_dir, *, include=None):
        destination = Path(staging_dir) / "home" / "masteruser" / ".bashrc"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.payload)
        return Path(staging_dir)

    def dump_snapshot_file(self, snapshot_id, path):
        return self.payload


def test_restore_probe_restores_hashes_and_cleans_staging(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    data = maintenance._job(job["id"])
    root = tmp_path / "verification"
    monkeypatch.setenv("LATTICE_BACKUP_VERIFICATION_STAGING_ROOT", str(root))
    repo = RestoreProbeRepo("/repo", "/password")

    result = maintenance.verify_restore_probe(repo, data)

    assert result["snapshot_id"] == "snap"
    assert result["path"] == "/home/masteruser/.bashrc"
    assert result["size"] == len(repo.payload)
    assert len(result["sha256"]) == 64
    assert root.exists()
    assert list(root.iterdir()) == []


def test_restore_probe_detects_mismatch_and_cleans_staging(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    data = maintenance._job(job["id"])
    root = tmp_path / "verification"
    monkeypatch.setenv("LATTICE_BACKUP_VERIFICATION_STAGING_ROOT", str(root))

    class BadRepo(RestoreProbeRepo):
        def dump_snapshot_file(self, snapshot_id, path):
            return b"different-backup-data"

    with pytest.raises(
        maintenance.BackupMaintenanceError,
        match="did not match repository data",
    ):
        maintenance.verify_restore_probe(BadRepo("/repo", "/password"), data)

    assert root.exists()
    assert list(root.iterdir()) == []


def test_deep_verify_runs_restore_probe_but_quick_does_not(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    data = maintenance._job(job["id"])
    repo = RestoreProbeRepo("/repo", "/password")
    calls = []
    monkeypatch.setattr(
        maintenance,
        "verify_restore_probe",
        lambda _repo, _job: calls.append((_repo, _job)) or {},
    )

    maintenance._verify(repo, data, deep=False)
    assert calls == []
    assert repo.checks == [None]

    maintenance._verify(repo, data, deep=True)
    assert len(calls) == 1
    assert calls[0][1]["id"] == job["id"]
    assert repo.checks[-1] == "5%"


def test_restore_probe_rejects_when_no_small_file_exists(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    data = maintenance._job(job["id"])

    class HugeRepo(RestoreProbeRepo):
        def list_snapshot_directory(self, snapshot_id, directory, limit=500):
            return [
                BackupEntry(
                    path="/home/masteruser/huge.bin",
                    name="huge.bin",
                    entry_type="file",
                    size=maintenance.MAX_RESTORE_PROBE_BYTES + 1,
                    modified_at=None,
                )
            ]

    with pytest.raises(
        maintenance.BackupMaintenanceError,
        match="No small regular file",
    ):
        maintenance.verify_restore_probe(HugeRepo("/repo", "/password"), data)
