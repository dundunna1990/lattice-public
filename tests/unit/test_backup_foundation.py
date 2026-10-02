from pathlib import Path
import subprocess
import uuid

import pytest

from lattice.backup.credentials import BackupCredentialError, create_password_file, validate_password_file
from lattice.backup.models import MountIdentity
from lattice.backup.restic import ResticError, ResticRepository
from lattice.backup.targets import BackupTargetError, LocalBackupTarget


def _target(tmp_path: Path) -> LocalBackupTarget:
    mount = tmp_path / "drive"
    repo = mount / "LatticeBackups"
    mount.mkdir()
    repo.mkdir()
    return LocalBackupTarget(str(uuid.uuid4()), "Test Backup", "FS-123", mount, repo)


def _identity(target: LocalBackupTarget, *, uuid_value: str = "FS-123", options=frozenset({"rw"})):
    return MountIdentity(Path(target.mount_path), uuid_value, "/dev/test", "ext4", options)


def test_target_rejects_wrong_physical_filesystem(tmp_path):
    target = _target(tmp_path)
    with pytest.raises(BackupTargetError, match="identity does not match"):
        target.validate(inspector=lambda _: _identity(target, uuid_value="OTHER"))


def test_target_rejects_read_only_filesystem(tmp_path):
    target = _target(tmp_path)
    with pytest.raises(BackupTargetError, match="read-only"):
        target.validate(inspector=lambda _: _identity(target, options=frozenset({"ro"})))


def test_password_file_is_created_private_and_reused(tmp_path):
    path = tmp_path / "repo.password"
    first = create_password_file(path)
    original = first.read_bytes()
    second = create_password_file(path)
    assert second == first
    assert second.read_bytes() == original
    assert second.stat().st_mode & 0o077 == 0
    assert len(original.strip()) >= 20


def test_password_file_rejects_broad_permissions(tmp_path):
    path = tmp_path / "repo.password"
    path.write_text("a" * 40)
    path.chmod(0o644)
    with pytest.raises(BackupCredentialError, match="permissions"):
        validate_password_file(path)


def test_restic_requires_binary(tmp_path, monkeypatch):
    password = create_password_file(tmp_path / "pw")
    monkeypatch.setenv("LATTICE_RESTIC_BINARY", str(tmp_path / "missing-restic"))
    monkeypatch.setattr("lattice.backup.restic.shutil.which", lambda _: None)
    with pytest.raises(ResticError, match="not installed"):
        ResticRepository(tmp_path / "repo", password)


def test_restic_builds_commands_without_shell_and_parses_snapshots(tmp_path, monkeypatch):
    password = create_password_file(tmp_path / "pw")
    monkeypatch.setattr("lattice.backup.restic.shutil.which", lambda _: "/usr/bin/restic")
    calls = []
    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, '[{"id":"abc123","time":"2026-09-03T02:00:00Z","hostname":"node","paths":["/home/user"]}]', "")
    monkeypatch.setattr("lattice.backup.restic.subprocess.run", fake_run)
    repo = ResticRepository(tmp_path / "repo", password, binary="/usr/bin/restic")
    snapshots = repo.snapshots()
    assert snapshots[0].snapshot_id == "abc123"
    command, kwargs = calls[0]
    assert command[:5] == ["/usr/bin/restic", "--repo", str(tmp_path / "repo"), "--password-file", str(password)]
    assert "--cache-dir" in command
    assert command[command.index("--cache-dir") + 1] == "/var/lib/lattice-root/restic-cache"
    assert command[-2:] == ["snapshots", "--json"]
    assert "shell" not in kwargs


def test_repository_state_probe_ignores_stale_repository_locks(tmp_path, monkeypatch):
    password = create_password_file(tmp_path / "pw")
    monkeypatch.setattr("lattice.backup.restic.shutil.which", lambda _: "/usr/bin/restic")
    calls = []
    monkeypatch.setattr(
        "lattice.backup.restic.subprocess.run",
        lambda command, **kwargs: calls.append(command)
        or subprocess.CompletedProcess(command, 0, "", ""),
    )
    repo = ResticRepository(tmp_path / "repo", password, binary="/usr/bin/restic")
    assert repo.repository_state() == "initialized"
    assert "--no-lock" in calls[0]
    assert calls[0][-2:] == ["cat", "config"]


def test_restic_backup_uses_filesystem_and_cache_safety_flags(tmp_path, monkeypatch):
    password = create_password_file(tmp_path / "pw")
    monkeypatch.setattr("lattice.backup.restic.shutil.which", lambda _: "/usr/bin/restic")
    calls = []
    monkeypatch.setattr(
        "lattice.backup.restic.subprocess.run",
        lambda command, **kwargs: calls.append(command)
        or subprocess.CompletedProcess(command, 0, "", ""),
    )
    repo = ResticRepository(tmp_path / "repo", password, binary="/usr/bin/restic")
    repo.backup(Path("/home/user"), excludes=[Path("/home/user/Lattice/peer")], hostname="node")
    command = calls[0]
    assert "--one-file-system" in command
    assert "--exclude-caches" in command
    marker_indexes = [
        index for index, value in enumerate(command)
        if value == "--exclude-if-present"
    ]
    assert [command[index + 1] for index in marker_indexes] == [
        ".lattice-exclude-dir",
        "pyvenv.cfg",
    ]
    assert command[command.index("--exclude") + 1] == "/home/user/Lattice/peer"


def test_restore_only_targets_staging(tmp_path, monkeypatch):
    password = create_password_file(tmp_path / "pw")
    monkeypatch.setattr("lattice.backup.restic.shutil.which", lambda _: "/usr/bin/restic")
    calls = []
    monkeypatch.setattr("lattice.backup.restic.subprocess.run", lambda command, **kwargs: calls.append(command) or subprocess.CompletedProcess(command, 0, "", ""))
    repo = ResticRepository(tmp_path / "repo", password)
    staging = tmp_path / "staging"
    repo.restore_to_staging("abcdef", staging, include="/home/user/Documents")
    assert "--target" in calls[0]
    assert str(staging) in calls[0]
    assert "/home/user" != str(staging)


def test_storage_discovery_returns_mounted_uuid_filesystems_and_external_first():
    import json
    import subprocess
    from lattice.backup.discovery import discover_storage

    payload = {"blockdevices": [{"name":"sda","path":"/dev/sda","type":"disk","children":[
        {"name":"sda1","path":"/dev/sda1","type":"part","fstype":"ext4","uuid":"root-uuid","mountpoints":["/"],"size":1000,"rm":0},
        {"name":"sdb1","path":"/dev/sdb1","type":"part","fstype":"ext4","uuid":"backup-uuid","mountpoints":["/mnt/backup"],"size":4000,"rm":1}
    ]}]}
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, json.dumps(payload), "")
    found = discover_storage(runner=runner)
    assert [item.filesystem_uuid for item in found] == ["backup-uuid", "root-uuid"]
    assert found[0].mountpoint == "/mnt/backup"
    assert found[0].removable is True


def test_storage_discovery_ignores_unmounted_and_uuid_less_filesystems():
    import json
    import subprocess
    from lattice.backup.discovery import discover_storage

    payload = {"blockdevices": [
        {"name":"sdb1","path":"/dev/sdb1","type":"part","fstype":"ext4","uuid":"u1","mountpoints":[None],"size":4000,"rm":1},
        {"name":"sdc1","path":"/dev/sdc1","type":"part","fstype":"ext4","uuid":None,"mountpoints":["/mnt/x"],"size":4000,"rm":1}
    ]}
    def runner(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, json.dumps(payload), "")
    assert discover_storage(runner=runner) == []


def test_backup_migrations_create_domain_tables(tmp_path):
    import sqlite3
    from lattice.core.migrations import run_migrations

    db = tmp_path / "state.sqlite"
    conn = sqlite3.connect(db)
    try:
        run_migrations(conn)
        names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert {"backup_targets", "backup_jobs", "backup_runs", "backup_target_observations"} <= names


def test_backup_catalog_lists_active_sources_and_registered_targets(tmp_path, monkeypatch):
    import sqlite3
    import uuid
    from lattice.core.migrations import run_migrations
    from lattice.backup.catalog import backup_source_computers, registered_backup_targets

    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    master_id = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())
    conn.execute("INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?,?)", (master_id,"master-node","master","masteruser",1000,1000,"active"))
    conn.execute("INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?,?)", (worker_id,"worker-node","worker","workeruser",1000,1000,"active"))
    conn.execute("INSERT INTO backup_targets(target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,repository_root) VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()),"Backup Drive",worker_id,"remote_storage","disk-uuid","/mnt/backup/LatticeBackups"))
    conn.commit()
    conn.close()

    sources = backup_source_computers()
    targets = registered_backup_targets()
    assert [item["hostname"] for item in sources] == ["master-node", "worker-node"]
    assert targets[0]["friendly_name"] == "Backup Drive"
    assert targets[0]["host_hostname"] == "worker-node"


def _seed_active_nodes(db_path, monkeypatch):
    import sqlite3, uuid
    from lattice.core.migrations import run_migrations
    monkeypatch.setenv("LATTICE_DB_PATH", str(db_path))
    conn = sqlite3.connect(db_path)
    run_migrations(conn)
    master = str(uuid.uuid4())
    worker = str(uuid.uuid4())
    conn.execute("INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?,?)", (master,"master-node","master","masteruser",1000,1000,"active"))
    conn.execute("INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?,?)", (worker,"backup-node","worker","backupuser",1001,1001,"active"))
    conn.commit(); conn.close()
    return master, worker


def test_register_target_and_create_home_job(tmp_path, monkeypatch):
    from lattice.backup.jobs import register_target, create_job
    master, backup_node = _seed_active_nodes(tmp_path / "state.sqlite", monkeypatch)
    target = register_target(friendly_name="Backup Drive", host_node_id=backup_node, filesystem_uuid="backup-disk", repository_root="/mnt/backup/LatticeBackups", target_type="remote_storage")
    job = create_job(source_node_id=master, target_id=target["id"], source_path="/home/masteruser")
    assert target["friendly_name"] == "Backup Drive"
    assert job["source_node_id"] == master
    assert job["target_id"] == target["id"]


def test_create_job_rejects_arbitrary_source_path(tmp_path, monkeypatch):
    import pytest
    from lattice.backup.jobs import register_target, create_job, BackupJobError
    master, backup_node = _seed_active_nodes(tmp_path / "state.sqlite", monkeypatch)
    target = register_target(friendly_name="Drive", host_node_id=backup_node, filesystem_uuid="disk", repository_root="/mnt/backup/LatticeBackups", target_type="remote_storage")
    with pytest.raises(BackupJobError, match="Home directory"):
        create_job(source_node_id=master, target_id=target["id"], source_path="/etc")


def test_pause_requires_reason_and_resume_clears_it(tmp_path, monkeypatch):
    import pytest
    from lattice.backup.jobs import register_target, create_job, set_job_paused, BackupJobError
    master, backup_node = _seed_active_nodes(tmp_path / "state.sqlite", monkeypatch)
    target = register_target(friendly_name="Drive", host_node_id=backup_node, filesystem_uuid="disk", repository_root="/mnt/backup/LatticeBackups", target_type="remote_storage")
    job = create_job(source_node_id=master, target_id=target["id"], source_path="/home/masteruser")
    with pytest.raises(BackupJobError, match="pause reason"):
        set_job_paused(job["id"], paused=True)
    paused = set_job_paused(job["id"], paused=True, reason="operator requested")
    assert paused["paused"] == 1 and paused["pause_reason"] == "operator requested"
    resumed = set_job_paused(job["id"], paused=False)
    assert resumed["paused"] == 0 and resumed["pause_reason"] is None


def test_uuid_mount_lookup_uses_portable_findmnt_source_selector(monkeypatch):
    from lattice.backup import targets

    seen = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        return subprocess.CompletedProcess(
            args,
            0,
            stdout='{"filesystems":[{"target":"/mnt/backup","uuid":"drive-uuid","source":"/dev/sda4","fstype":"ext4","options":"rw,relatime"},{"target":"/srv/lattice-backup-chroot/a/repo","uuid":"drive-uuid","source":"/dev/sda4[/LatticeBackups/a]","fstype":"ext4","options":"rw,relatime"},{"target":"/srv/lattice-backup-chroot/b/repo","uuid":"drive-uuid","source":"/dev/sda4[/LatticeBackups/b]","fstype":"ext4","options":"rw,relatime"}]}',
            stderr="",
        )

    monkeypatch.setattr(targets.subprocess, "run", fake_run)
    result = targets.inspect_uuid_mount("drive-uuid")
    assert seen["args"][:4] == [
        "findmnt",
        "--json",
        "--source",
        "UUID=drive-uuid",
    ]
    assert result.target == Path("/mnt/backup")
    assert result.filesystem_uuid == "drive-uuid"


def test_repository_validation_follows_uuid_when_mountpoint_changes(tmp_path):
    from lattice.backup.targets import validate_repository_target

    current_mount = tmp_path / "new-mount"
    repository = current_mount / "LatticeBackups"
    current_mount.mkdir()
    identity = MountIdentity(
        current_mount.resolve(), "same-drive-uuid", "/dev/sdb1", "ext4", frozenset({"rw"})
    )
    validated = validate_repository_target(
        repository,
        "same-drive-uuid",
        inspector=lambda _path: identity,
        require_writable=False,
    )
    assert validated.target == current_mount.resolve()


def test_register_discovered_target_uses_opaque_candidate(tmp_path, monkeypatch):
    from datetime import datetime, timezone
    from lattice.backup.jobs import register_discovered_target

    candidate = {
        "candidate_id": "a" * 20,
        "host_node_id": str(uuid.uuid4()),
        "host_hostname": "backup-node",
        "name": "sdb1",
        "filesystem_type": "ext4",
        "size_bytes": 4_000_000_000_000,
        "removable": True,
        "registered": False,
        "registered_target_id": None,
        "registered_target_name": None,
        "filesystem_uuid": "drive-uuid",
        "device": "/dev/sdb1",
        "mountpoint": "/media/backup",
        "last_reported_at": datetime.now(timezone.utc).isoformat(),
    }
    monkeypatch.setattr(
        "lattice.backup.catalog.fleet_storage_candidates",
        lambda include_sensitive=False: [candidate],
    )
    seen = {}
    monkeypatch.setattr(
        "lattice.backup.jobs.register_target",
        lambda **kwargs: seen.update(kwargs) or {"id": 7, **kwargs},
    )
    result = register_discovered_target("a" * 20, friendly_name="Backup Drive")
    assert result["id"] == 7
    assert seen["host_node_id"] == candidate["host_node_id"]
    assert seen["filesystem_uuid"] == "drive-uuid"
    assert seen["repository_root"] == "/media/backup/LatticeBackups"


def test_register_discovered_target_rejects_stale_remote_candidate(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from lattice.backup.jobs import BackupJobError, register_discovered_target

    candidate = {
        "candidate_id": "b" * 20,
        "host_node_id": str(uuid.uuid4()),
        "host_hostname": "backup-node",
        "name": "sdb1",
        "filesystem_type": "ext4",
        "size_bytes": 1000,
        "removable": True,
        "registered": False,
        "registered_target_id": None,
        "registered_target_name": None,
        "filesystem_uuid": "drive-uuid",
        "device": "/dev/sdb1",
        "mountpoint": "/media/backup",
        "last_reported_at": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
    }
    monkeypatch.setattr(
        "lattice.backup.catalog.fleet_storage_candidates",
        lambda include_sensitive=False: [candidate],
    )
    with pytest.raises(BackupJobError, match="stale or offline"):
        register_discovered_target("b" * 20, friendly_name="Old Drive")


def test_register_target_rejects_non_v1_repository_root(tmp_path, monkeypatch):
    import sqlite3
    from lattice.backup.jobs import BackupJobError, register_target
    from lattice.core.migrations import run_migrations

    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (node, 'backup-node', 'worker', 'backupuser', 1000, 1000),
    )
    conn.commit(); conn.close()
    with pytest.raises(BackupJobError, match='LatticeBackups folder'):
        register_target(
            friendly_name='Bad Layout',
            host_node_id=node,
            filesystem_uuid='disk-uuid',
            repository_root='/mnt/backup/custom/nested',
            target_type='local_storage',
        )
