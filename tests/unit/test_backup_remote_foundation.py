from pathlib import Path
import uuid

import pytest

from lattice.backup.assignment import (
    BackupAssignmentError,
    normalize_assignment,
    sign_assignment,
    verify_assignment,
)
from lattice.backup.keys import ensure_backup_client_identity, ensure_backup_host_identity
from lattice.backup.transport import (
    BackupTransportAccount,
    BackupTransportError,
    backup_account_name,
    render_authorized_key,
    render_sshd_config,
)
from lattice.file_access.keys import ensure_fleet_signing_identity


def _assignment(public_key: str, host_public_key: str) -> dict:
    return {
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": 1,
        "assignments": [{
            "source_node_id": str(uuid.uuid4()),
            "target_node_id": str(uuid.uuid4()),
            "target_uuid": str(uuid.uuid4()),
            "repository_id": str(uuid.uuid4()),
            "backup_public_key": public_key,
            "backup_host_public_key": host_public_key,
            "backup_host_key_fingerprint": __import__("lattice.file_access.keys", fromlist=["fingerprint_ed25519_public_key"]).fingerprint_ed25519_public_key(host_public_key),
        }],
    }


def test_backup_client_and_host_keys_are_separate(tmp_path):
    client = ensure_backup_client_identity(tmp_path / "backup-ssh")
    host = ensure_backup_host_identity(tmp_path / "backup-ssh")
    assert client.public_key_text.split()[:2] != host.public_key_text.split()[:2]
    assert client.private_key != host.private_key


def test_signed_backup_assignment_round_trip_and_tamper_rejection(tmp_path):
    backup = ensure_backup_client_identity(tmp_path / "backup")
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    host = ensure_backup_host_identity(tmp_path / "target-backup")
    payload = _assignment(backup.public_key_text, host.public_key_text)
    signature = sign_assignment(payload, signer.private_key)
    assert verify_assignment(payload, signature, signer.public_key_text)
    tampered = {**payload, "generation": 2}
    assert not verify_assignment(tampered, signature, signer.public_key_text)


def test_assignment_rejects_local_remote_mixup(tmp_path):
    backup = ensure_backup_client_identity(tmp_path / "backup")
    host = ensure_backup_host_identity(tmp_path / "target-backup")
    payload = _assignment(backup.public_key_text, host.public_key_text)
    payload["assignments"][0]["target_node_id"] = payload["assignments"][0]["source_node_id"]
    with pytest.raises(BackupAssignmentError, match="different nodes"):
        normalize_assignment(payload)


def test_transport_uses_per_source_chroot_and_no_shell(tmp_path):
    key = ensure_backup_client_identity(tmp_path / "backup").public_key_text
    source = str(uuid.uuid4())
    target_uuid = str(uuid.uuid4())
    account = BackupTransportAccount(source, target_uuid, key)
    username = backup_account_name(source, target_uuid)
    assert len(username) == 32
    config = render_sshd_config([account])
    assert "Port 22024" in config
    assert f"AllowUsers {username}" in config
    assert f"ChrootDirectory /srv/lattice-backup-chroot/{username}" in config
    assert "ForceCommand internal-sftp -d /" in config
    assert "DisableForwarding yes" in config
    assert "PermitTTY no" in config
    assert "PasswordAuthentication no" in config
    assert "PermitRootLogin no" in config
    assert "restrict ssh-ed25519" in render_authorized_key(key)


def test_transport_refuses_duplicate_source_accounts(tmp_path):
    key = ensure_backup_client_identity(tmp_path / "backup").public_key_text
    source = str(uuid.uuid4())
    target_uuid = str(uuid.uuid4())
    account = BackupTransportAccount(source, target_uuid, key)
    with pytest.raises(BackupTransportError, match="duplicated"):
        render_sshd_config([account, account])


def test_restic_sftp_repository_uses_lattice_ssh_args_without_shell(tmp_path, monkeypatch):
    import subprocess
    from lattice.backup.credentials import create_password_file
    from lattice.backup.restic import ResticSFTPRepository

    password = create_password_file(tmp_path / "pw")
    monkeypatch.setattr("lattice.backup.restic.shutil.which", lambda _: "/usr/bin/restic")
    calls = []
    monkeypatch.setattr(
        "lattice.backup.restic.subprocess.run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "[]", ""),
    )
    repo = ResticSFTPRepository(
        "sftp:lattice-bkp-1234567890abcdef1234@10.0.0.2:repo",
        password,
        ssh_args=("-p", "22024", "-o", "BatchMode=yes"),
        binary="/usr/bin/restic",
    )
    repo.snapshots()
    command, kwargs = calls[0]
    assert command[:5] == [
        "/usr/bin/restic", "--repo",
        "sftp:lattice-bkp-1234567890abcdef1234@10.0.0.2:repo",
        "--password-file", str(password),
    ]
    assert "-o" in command
    assert any(value.startswith("sftp.args=") for value in command)
    assert "shell" not in kwargs


def test_local_transport_plan_requires_signed_target_and_physical_drive(tmp_path, monkeypatch):
    import sqlite3
    from lattice.backup.transport_plan import build_local_transport_plan
    from lattice.core.migrations import run_migrations

    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    source = str(uuid.uuid4())
    target_node = str(uuid.uuid4())
    target_uuid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (target_node, "backup-node", "worker", "backupuser", 1000, 1000),
    )
    conn.execute(
        "INSERT INTO backup_targets(target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,repository_root) VALUES(?,?,?,?,?,?)",
        (target_uuid, "Backup Drive", target_node, "remote_storage", "disk-1", "/mnt/backup/LatticeBackups"),
    )
    conn.commit(); conn.close()

    client = ensure_backup_client_identity(tmp_path / "source-backup")
    host = ensure_backup_host_identity(tmp_path / "target-backup")
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    payload = {
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": 1,
        "assignments": [{
            "source_node_id": source,
            "target_node_id": target_node,
            "target_uuid": target_uuid,
            "repository_id": str(uuid.uuid4()),
            "backup_public_key": client.public_key_text,
            "backup_host_public_key": host.public_key_text,
            "backup_host_key_fingerprint": host.fingerprint,
        }],
    }
    signature = sign_assignment(payload, signer.private_key)
    validated = []
    plan = build_local_transport_plan(
        payload,
        signature,
        signer.public_key_text,
        local_node_id=target_node,
        local_host_public_key=host.public_key_text,
        target_resolver=lambda fs_uuid, relative: (Path("/mnt/backup/LatticeBackups"), validated.append((relative, fs_uuid)) or None),
    )
    assert validated == [("LatticeBackups", "disk-1")]
    assert len(plan) == 1
    assert plan[0].repository_path == Path("/mnt/backup/LatticeBackups") / source
    assert plan[0].account.public_key == client.public_key_text


def test_local_transport_plan_rejects_wrong_local_host_key(tmp_path, monkeypatch):
    import sqlite3
    from lattice.backup.transport_plan import BackupTransportPlanError, build_local_transport_plan
    from lattice.core.migrations import run_migrations

    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db); run_migrations(conn)
    source, target_node, target_uuid = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state) VALUES(?,?,?,?,?,?, 'active')",
        (target_node, "backup-node", "worker", "backupuser", 1000, 1000),
    )
    conn.execute(
        "INSERT INTO backup_targets(target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,repository_root) VALUES(?,?,?,?,?,?)",
        (target_uuid, "Drive", target_node, "remote_storage", "disk", "/mnt/backup/LatticeBackups"),
    )
    conn.commit(); conn.close()
    client = ensure_backup_client_identity(tmp_path / "source")
    host = ensure_backup_host_identity(tmp_path / "host")
    wrong_host = ensure_backup_host_identity(tmp_path / "wrong-host")
    signer = ensure_fleet_signing_identity(tmp_path / "signer")
    payload = {
        "schema_version": 1, "fleet_id": str(uuid.uuid4()), "generation": 1,
        "assignments": [{
            "source_node_id": source, "target_node_id": target_node,
            "target_uuid": target_uuid, "repository_id": str(uuid.uuid4()),
            "backup_public_key": client.public_key_text,
            "backup_host_public_key": host.public_key_text,
            "backup_host_key_fingerprint": host.fingerprint,
        }],
    }
    signature = sign_assignment(payload, signer.private_key)
    with pytest.raises(BackupTransportPlanError, match="wrong local backup host key"):
        build_local_transport_plan(
            payload, signature, signer.public_key_text,
            local_node_id=target_node,
            local_host_public_key=wrong_host.public_key_text,
            target_resolver=lambda *args: (Path("/mnt/backup/LatticeBackups"), None),
        )


def test_same_source_two_targets_get_distinct_transport_accounts():
    source = str(uuid.uuid4())
    first = str(uuid.uuid4())
    second = str(uuid.uuid4())
    assert backup_account_name(source, first) != backup_account_name(source, second)


def test_restic_sftp_repository_applies_upload_limit(tmp_path):
    from lattice.backup.restic import ResticSFTPRepository

    password = tmp_path / 'password'
    password.write_text('x' * 64)
    password.chmod(0o600)
    repo = ResticSFTPRepository(
        'sftp:lattice@10.0.0.3:repo',
        password,
        ssh_args=('-p', '22024', '-o', 'BatchMode=yes'),
        upload_limit_kib=4096,
        binary='/bin/true',
    )
    assert '--limit-upload' in repo.backend_options
    index = repo.backend_options.index('--limit-upload')
    assert repo.backend_options[index + 1] == '4096'
