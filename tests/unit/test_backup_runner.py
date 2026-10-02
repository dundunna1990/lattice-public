from pathlib import Path
from types import SimpleNamespace
import sqlite3
import uuid

import pytest

from lattice.backup.jobs import create_job, register_target
from lattice.backup.models import BackupSnapshot, MountIdentity
from lattice.backup.runner import BackupExecutionError, run_local_job, run_remote_job
from lattice.backup.targets import LocalBackupTarget
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch):
    db=tmp_path/'state.sqlite'; monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    monkeypatch.setattr(
        "lattice.backup.runner.run_preflight",
        lambda *args, **kwargs: SimpleNamespace(warnings=()),
    )
    monkeypatch.setattr(
        "lattice.backup.runner.record_successful_preflight",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setenv('LATTICE_MOUNT_PLAN_PATH', str(tmp_path / 'mount-plans.json'))
    conn=sqlite3.connect(db); run_migrations(conn)
    node=str(uuid.uuid4())
    conn.execute("INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')", (node,'backup-node','worker','backupuser',1000,1000)); conn.commit(); conn.close()
    mount=tmp_path/'drive'; repo_root=mount/'LatticeBackups'; repo_root.mkdir(parents=True)
    target=register_target(friendly_name='Backup Drive', host_node_id=node, filesystem_uuid='disk-uuid', repository_root=str(repo_root), target_type='local_storage')
    job=create_job(source_node_id=node, target_id=target['id'], source_path='/home/backupuser')
    return job, mount, repo_root

class _Target(LocalBackupTarget):
    def validate(self, **kwargs):
        return MountIdentity(self.mount_path, self.filesystem_uuid, '/dev/test', 'ext4', frozenset({'rw'}))

class _Repo:
    def __init__(self, repository, password_file): self.repository=Path(repository); self.password_file=password_file; self.inited=False
    def initialize(self): self.repository.mkdir(parents=True); self.inited=True
    def clear_stale_locks(self): return None
    def backup(self, source, *, excludes=(), hostname=None): assert source == Path('/home/backupuser'); assert hostname == 'backup-node'
    def snapshots(self): return [BackupSnapshot('snap1','2026-09-03T02:00:00Z','backup-node',('/home/backupuser',))]
    def check(self): return None

def test_local_runner_records_verified_success(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    result=run_local_job(job['id'], credential_root=tmp_path/'creds', repository_factory=_Repo, target_factory=_Target, local_node_id=job['source_node_id'])
    assert result['result']=='successful'; assert result['snapshot_id']=='snap1'

def test_local_runner_clears_stale_locks_before_backup(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    calls = []

    class Repo(_Repo):
        def clear_stale_locks(self):
            calls.append("cleanup")

        def backup(self, source, *, excludes=(), hostname=None):
            calls.append("backup")
            return super().backup(source, excludes=excludes, hostname=hostname)

    result = run_local_job(
        job["id"],
        credential_root=tmp_path / "creds",
        repository_factory=Repo,
        target_factory=_Target,
        local_node_id=job["source_node_id"],
    )

    assert result["result"] == "successful"
    assert calls[:2] == ["cleanup", "backup"]


def test_local_runner_rejects_target_hosted_by_other_computer(tmp_path, monkeypatch):
    job, _, _ = _setup(tmp_path, monkeypatch)
    db = Path(__import__('os').environ['LATTICE_DB_PATH'])
    conn = sqlite3.connect(db)
    other = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (other, 'worker-node', 'worker', 'workeruser', 1000, 1000),
    )
    conn.execute(
        "UPDATE backup_targets SET host_node_id=? WHERE id=(SELECT target_id FROM backup_jobs WHERE id=?)",
        (other, job['id']),
    )
    conn.commit(); conn.close()
    with pytest.raises(BackupExecutionError, match='hosted by a different computer'):
        run_local_job(
            job['id'], credential_root=tmp_path/'creds', repository_factory=_Repo,
            target_factory=_Target, local_node_id=job['source_node_id'],
        )

def test_default_excludes_managed_lattice_links_but_keeps_personal_entries(tmp_path, monkeypatch):
    from lattice.backup.source_policy import default_excludes

    home = tmp_path / "home"
    lattice_home = home / "Lattice"
    mount_root = tmp_path / "mnt" / "lattice"
    managed_target = mount_root / "peer-node"
    personal_target = tmp_path / "personal-target"
    lattice_home.mkdir(parents=True)
    managed_target.mkdir(parents=True)
    personal_target.mkdir()

    managed_link = lattice_home / "peer-node"
    personal_link = lattice_home / "personal-link"
    managed_link.symlink_to(managed_target)
    personal_link.symlink_to(personal_target)

    plan_path = tmp_path / "mount-plans.json"
    plan_path.write_text(
        '{"visible_peers":[{"hostname":"planned-peer","node_id":"planned-node"}]}'
    )
    monkeypatch.setenv("LATTICE_MOUNT_ROOT", str(mount_root))
    monkeypatch.setenv("LATTICE_MOUNT_PLAN_PATH", str(plan_path))
    monkeypatch.setattr(
        "lattice.backup.source_policy.mounted_paths_under",
        lambda _source: [],
    )

    excludes = default_excludes(home)

    assert managed_link in excludes
    assert lattice_home / "planned-peer" in excludes
    assert personal_link not in excludes
    assert lattice_home not in excludes


def test_default_excludes_known_regenerable_data_without_dropping_identity_state(tmp_path, monkeypatch):
    from lattice.backup.source_policy import default_excludes

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("LATTICE_MOUNT_PLAN_PATH", str(tmp_path / "mount-plans.json"))
    monkeypatch.setattr(
        "lattice.backup.source_policy.mounted_paths_under",
        lambda _source: [],
    )

    excludes = {str(path) for path in default_excludes(home)}

    assert str(home / ".npm") in excludes
    assert str(home / ".cargo/registry") in excludes
    assert str(home / ".local/share/flatpak/repo") in excludes
    assert str(home / ".mozilla/firefox/*/cache2") in excludes
    assert str(home / ".config/google-chrome/*/Cache") in excludes
    assert str(home / "**/node_modules") in excludes
    assert str(home / "**/.venv") in excludes
    assert str(home / "**/__pycache__") in excludes
    assert str(home / ".steam/debian-installation/config/htmlcache/*/Code Cache") in excludes
    assert str(home / ".steam/debian-installation/steamapps/common") in excludes
    assert str(home / ".steam/debian-installation/steamapps/shadercache") in excludes
    assert str(home / "Android/Sdk") in excludes
    assert str(home / "**/android/app/build") in excludes
    assert str(home / "**/android/build") in excludes

    assert str(home / ".ssh") not in excludes
    assert str(home / ".gnupg") not in excludes
    assert str(home / ".mozilla") not in excludes
    assert str(home / ".config") not in excludes
    assert str(home / ".local/share") not in excludes
    assert str(home / ".var/app/*/data") not in excludes
    assert str(home / ".steam/debian-installation/userdata") not in excludes
    assert str(home / ".steam/debian-installation/steamapps/compatdata") not in excludes
    assert str(home / ".android/avd") not in excludes
    assert str(home / "projects/example/android/app/src") not in excludes


def test_runner_passes_safe_default_exclusions(tmp_path, monkeypatch):
    job, _, repo_root = _setup(tmp_path, monkeypatch)
    seen = {}
    class Repo(_Repo):
        def backup(self, source, *, excludes=(), hostname=None):
            seen['source'] = source
            seen['excludes'] = tuple(Path(p) for p in excludes)
            seen['hostname'] = hostname
    monkeypatch.setattr('lattice.backup.source_policy.mounted_paths_under', lambda source: [Path('/home/backupuser/Lattice/peer')])
    # runner imported the function directly, so replace its global helper too.
    monkeypatch.setattr('lattice.backup.runner.default_excludes', lambda source, repository_path=None: [Path('/home/backupuser/.cache'), Path('/home/backupuser/Lattice/peer')])
    run_local_job(job['id'], credential_root=tmp_path/'creds', repository_factory=Repo, target_factory=_Target, local_node_id=job['source_node_id'])
    assert Path('/home/backupuser/.cache') in seen['excludes']
    assert Path('/home/backupuser/Lattice/peer') in seen['excludes']


def _setup_remote(tmp_path, monkeypatch):
    db = tmp_path / "remote.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    monkeypatch.setattr(
        "lattice.backup.runner.run_preflight",
        lambda *args, **kwargs: SimpleNamespace(warnings=()),
    )
    monkeypatch.setattr(
        "lattice.backup.runner.record_successful_preflight",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "lattice.backup.runner.sftp_capacity",
        lambda _connection: (1000 * 1024**3, 900 * 1024**3),
    )
    monkeypatch.setenv("LATTICE_MOUNT_PLAN_PATH", str(tmp_path / "mount-plans.json"))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    source = str(uuid.uuid4())
    target_node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (source, "worker-node", "worker", "workeruser", 1000, 1000),
    )
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (target_node, "backup-node", "worker", "backupuser", 1000, 1000),
    )
    conn.commit()
    conn.close()
    target = register_target(
        friendly_name="Backup Drive",
        host_node_id=target_node,
        filesystem_uuid="disk-uuid",
        repository_root="/mnt/backup/LatticeBackups",
        target_type="remote_storage",
    )
    job = create_job(
        source_node_id=source,
        target_id=target["id"],
        source_path="/home/workeruser",
    )
    return job


class _RemoteRepo:
    seen_upload_limits = []

    def __init__(self, repository, password_file, *, ssh_args, upload_limit_kib=None):
        self.repository = repository
        self.password_file = password_file
        self.ssh_args = tuple(ssh_args)
        self.upload_limit_kib = upload_limit_kib
        self.__class__.seen_upload_limits.append(upload_limit_kib)

    def repository_state(self):
        return "initialized"

    def initialize(self):
        return None

    def clear_stale_locks(self):
        return None

    def backup(self, source, *, excludes=(), hostname=None):
        assert source == Path('/home/workeruser')
        assert hostname == 'worker-node'

    def snapshots(self):
        return [
            BackupSnapshot(
                'remote-snap',
                '2026-09-03T02:00:00Z',
                'worker-node',
                ('/home/workeruser',),
            )
        ]

    def check(self):
        return None


def test_remote_runner_records_verified_success(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    connection = SimpleNamespace(
        host='10.0.0.3',
        repository='sftp:test@10.0.0.3:repo',
        ssh_args=('-p', '22024'),
    )
    monkeypatch.setattr(
        'lattice.backup.runner.default_excludes',
        lambda source, repository_path=None: [Path('/home/workeruser/.cache')],
    )
    monkeypatch.setattr(
        'lattice.backup.runner.runtime_policy',
        lambda: {'bandwidth_limit_kib': 0},
    )
    result = run_remote_job(
        job['id'],
        credential_root=tmp_path / 'creds',
        repository_factory=_RemoteRepo,
        connection_factory=lambda _job: [connection],
        local_node_id=job['source_node_id'],
    )
    assert result['result'] == 'successful'
    assert result['snapshot_id'] == 'remote-snap'




def test_remote_runner_runs_repository_cleanup_before_initialized_backup(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    connection = SimpleNamespace(
        host="10.0.0.3", repository="sftp:test@10.0.0.3:repo", ssh_args=("-p", "22024"),
    )
    calls = []

    class Repo(_RemoteRepo):
        def clear_stale_locks(self):
            calls.append("cleanup")

        def backup(self, source, *, excludes=(), hostname=None):
            calls.append("backup")
            return super().backup(source, excludes=excludes, hostname=hostname)

    monkeypatch.setattr("lattice.backup.runner.default_excludes", lambda source, repository_path=None: [])
    monkeypatch.setattr("lattice.backup.runner.runtime_policy", lambda: {"bandwidth_limit_kib": 0})

    result = run_remote_job(
        job["id"], credential_root=tmp_path / "creds", repository_factory=Repo,
        connection_factory=lambda _job: [connection], local_node_id=job["source_node_id"],
    )

    assert result["result"] == "successful"
    assert calls[:2] == ["cleanup", "backup"]


def test_remote_runner_stays_on_selected_route_after_verification_failure(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    first = SimpleNamespace(
        host="10.0.0.3", repository="sftp:test@10.0.0.3:repo", ssh_args=("-p", "22024"),
    )
    second = SimpleNamespace(
        host="10.0.0.4", repository="sftp:test@10.0.0.4:repo", ssh_args=("-p", "22024"),
    )
    constructed = []

    class Repo(_RemoteRepo):
        def __init__(self, repository, password_file, *, ssh_args, upload_limit_kib=None):
            super().__init__(
                repository, password_file, ssh_args=ssh_args, upload_limit_kib=upload_limit_kib
            )
            constructed.append(repository)

        def check(self):
            from lattice.backup.restic import ResticError
            raise ResticError("verification failed on selected route")

    monkeypatch.setattr("lattice.backup.runner.default_excludes", lambda source, repository_path=None: [])
    monkeypatch.setattr("lattice.backup.runner.runtime_policy", lambda: {"bandwidth_limit_kib": 0})

    with pytest.raises(BackupExecutionError, match="verification failed on selected route"):
        run_remote_job(
            job["id"], credential_root=tmp_path / "creds", repository_factory=Repo,
            connection_factory=lambda _job: [first, second], local_node_id=job["source_node_id"],
        )

    assert constructed == [first.repository]


def test_remote_runner_initializes_only_when_probe_proves_repository_absent(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    connection = SimpleNamespace(
        host="10.0.0.3", repository="sftp:test@10.0.0.3:repo", ssh_args=("-p", "22024"),
    )
    calls = {"init": 0}

    class Repo(_RemoteRepo):
        def repository_state(self):
            return "absent"

        def initialize(self):
            calls["init"] += 1

    monkeypatch.setattr("lattice.backup.runner.default_excludes", lambda source, repository_path=None: [])
    monkeypatch.setattr("lattice.backup.runner.runtime_policy", lambda: {"bandwidth_limit_kib": 0})
    result = run_remote_job(
        job["id"], credential_root=tmp_path / "creds", repository_factory=Repo,
        connection_factory=lambda _job: [connection], local_node_id=job["source_node_id"],
    )
    assert result["result"] == "successful"
    assert calls["init"] == 1


def test_remote_runner_never_reinitializes_missing_established_repository(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    db = Path(__import__("os").environ["LATTICE_DB_PATH"])
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO backup_runs(job_id,started_at,finished_at,result,snapshot_id) VALUES(?,?,?,?,?)",
        (job["id"], "2026-09-02T02:00:00+00:00", "2026-09-02T02:05:00+00:00", "successful", "old"),
    )
    conn.commit(); conn.close()
    credential_root = tmp_path / "creds"
    credential_root.mkdir()
    (credential_root / f"{job['job_uuid']}.password").write_text("existing-password-that-is-long-enough")
    __import__("os").chmod(credential_root / f"{job['job_uuid']}.password", 0o600)
    connection = SimpleNamespace(
        host="10.0.0.3", repository="sftp:test@10.0.0.3:repo", ssh_args=("-p", "22024"),
    )

    class Repo(_RemoteRepo):
        def repository_state(self):
            return "absent"

        def initialize(self):
            raise AssertionError("must not initialize established missing repository")

    monkeypatch.setattr("lattice.backup.runner.default_excludes", lambda source, repository_path=None: [])
    monkeypatch.setattr("lattice.backup.runner.runtime_policy", lambda: {"bandwidth_limit_kib": 0})
    with pytest.raises(BackupExecutionError, match="refusing to initialize"):
        run_remote_job(
            job["id"], credential_root=credential_root, repository_factory=Repo,
            connection_factory=lambda _job: [connection], local_node_id=job["source_node_id"],
        )

def test_remote_probe_failure_removes_uncommitted_new_credential(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    credential_root = tmp_path / "creds"
    connection = SimpleNamespace(
        host="10.0.0.3", repository="sftp:test@10.0.0.3:repo", ssh_args=("-p", "22024"),
    )

    class Repo(_RemoteRepo):
        def repository_state(self):
            raise __import__("lattice.backup.restic", fromlist=["ResticError"]).ResticError(
                "wrong password", returncode=12
            )

    monkeypatch.setattr("lattice.backup.runner.default_excludes", lambda source, repository_path=None: [])
    monkeypatch.setattr("lattice.backup.runner.runtime_policy", lambda: {"bandwidth_limit_kib": 0})
    with pytest.raises(BackupExecutionError, match="wrong password"):
        run_remote_job(
            job["id"], credential_root=credential_root, repository_factory=Repo,
            connection_factory=lambda _job: [connection], local_node_id=job["source_node_id"],
        )
    assert not (credential_root / f"{job['job_uuid']}.password").exists()


def test_remote_runner_rejects_job_owned_by_other_source(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    with pytest.raises(BackupExecutionError, match='different source computer'):
        run_remote_job(
            job['id'],
            credential_root=tmp_path / 'creds',
            repository_factory=_RemoteRepo,
            connection_factory=lambda _job: [],
            local_node_id=str(uuid.uuid4()),
        )


def test_remote_runner_applies_configured_bandwidth_limit(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    connection = SimpleNamespace(
        host='10.0.0.3', repository='sftp:test@10.0.0.3:repo',
        ssh_args=('-p', '22024'),
    )
    _RemoteRepo.seen_upload_limits = []
    monkeypatch.setattr(
        'lattice.backup.runner.default_excludes',
        lambda source, repository_path=None: [],
    )
    monkeypatch.setattr(
        'lattice.backup.runner.runtime_policy',
        lambda: {'bandwidth_limit_kib': 4096},
    )
    run_remote_job(
        job['id'], credential_root=tmp_path / 'creds',
        repository_factory=_RemoteRepo,
        connection_factory=lambda _job: [connection],
        local_node_id=job['source_node_id'],
    )
    assert _RemoteRepo.seen_upload_limits == [4096]


def test_remote_runner_full_speed_bypasses_cap_for_one_run(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    connection = SimpleNamespace(
        host='10.0.0.3', repository='sftp:test@10.0.0.3:repo',
        ssh_args=('-p', '22024'),
    )
    _RemoteRepo.seen_upload_limits = []
    monkeypatch.setattr(
        'lattice.backup.runner.default_excludes',
        lambda source, repository_path=None: [],
    )
    monkeypatch.setattr(
        'lattice.backup.runner.runtime_policy',
        lambda: {'bandwidth_limit_kib': 4096},
    )
    run_remote_job(
        job['id'], credential_root=tmp_path / 'creds',
        repository_factory=_RemoteRepo,
        connection_factory=lambda _job: [connection],
        local_node_id=job['source_node_id'],
        full_speed=True,
    )
    assert _RemoteRepo.seen_upload_limits == [None]


def test_local_runner_refuses_missing_credential_for_existing_repository(tmp_path, monkeypatch):
    job, _, repo_root = _setup(tmp_path, monkeypatch)
    repository = repo_root / job['source_node_id']
    repository.mkdir(parents=True, exist_ok=True)
    with pytest.raises(BackupExecutionError, match='credential is missing'):
        run_local_job(
            job['id'], credential_root=tmp_path / 'creds', repository_factory=_Repo,
            target_factory=_Target, local_node_id=job['source_node_id'],
        )
    assert not (tmp_path / 'creds' / f"{job['job_uuid']}.password").exists()


def test_remote_runner_refuses_missing_credential_after_prior_success(tmp_path, monkeypatch):
    job = _setup_remote(tmp_path, monkeypatch)
    db = Path(__import__('os').environ['LATTICE_DB_PATH'])
    conn = sqlite3.connect(db)
    conn.execute(
        "INSERT INTO backup_runs(job_id,started_at,finished_at,result,snapshot_id) VALUES(?,?,?,?,?)",
        (job['id'], '2026-09-02T02:00:00+00:00', '2026-09-02T02:05:00+00:00', 'successful', 'old-snap'),
    )
    conn.commit(); conn.close()
    with pytest.raises(BackupExecutionError, match='credential is missing'):
        run_remote_job(
            job['id'], credential_root=tmp_path / 'creds',
            repository_factory=_RemoteRepo,
            connection_factory=lambda _job: [],
            local_node_id=job['source_node_id'],
        )
    assert not (tmp_path / 'creds' / f"{job['job_uuid']}.password").exists()
