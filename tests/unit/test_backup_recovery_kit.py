import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from lattice.backup import recovery_kit
from lattice.backup.keys import ensure_backup_host_identity
from lattice.core.migrations import run_migrations


def _payload(tmp_path):
    host = ensure_backup_host_identity(tmp_path / "host-key")
    return {
        "schema_version": 1,
        "created_at": "2026-09-05T00:00:00+00:00",
        "source": {"node_id": str(uuid.uuid4()), "hostname": "source", "main_user": "user"},
        "backup_client_private_key": "fixture-client-material\n",
        "backup_client_public_key": host.public_key_text,
        "jobs": [{
            "job_uuid": str(uuid.uuid4()),
            "source_node_id": str(uuid.uuid4()),
            "source_path": "/home/user",
            "restic_password": "fixture-repository-material",
            "target_uuid": str(uuid.uuid4()),
            "target_node_id": str(uuid.uuid4()),
            "target_hostname": "target",
            "filesystem_uuid": "filesystem-uuid",
            "repository_relative_path": "LatticeBackups",
            "physical_repository": "/mnt/backup/LatticeBackups/source",
            "remote": True,
            "sftp_username": "lattice-bkp-0123456789abcdef0123",
            "sftp_port": 22024,
            "sftp_repository_path": "repo",
            "target_host_alias": "lattice-backup-node-target",
            "target_host_public_key": host.public_key_text,
            "known_routes": ["10.77.0.20"],
        }],
        "custody_warning": "separate storage",
    }


def test_encrypted_round_trip_and_extract_permissions(tmp_path, monkeypatch):
    payload = _payload(tmp_path)
    monkeypatch.setattr(recovery_kit, "build_recovery_payload", lambda: payload)
    encrypted = tmp_path / "source.recovery.enc"
    phrase = "correct horse battery staple"
    recovery_kit.export_recovery_kit(encrypted, phrase)
    ciphertext = encrypted.read_bytes()
    assert b"fixture-repository-material" not in ciphertext
    assert b"fixture-client-material" not in ciphertext
    assert encrypted.stat().st_mode & 0o777 == 0o600
    decoded = recovery_kit.decrypt_recovery_kit(encrypted, phrase)
    assert decoded["jobs"][0]["restic_password"] == "fixture-repository-material"
    workspace = recovery_kit.extract_recovery_kit(encrypted, tmp_path / "workspace", phrase)
    assert workspace.stat().st_mode & 0o777 == 0o700
    assert (workspace / "client_ed25519").stat().st_mode & 0o777 == 0o600
    pw = workspace / f"restic-{payload['jobs'][0]['job_uuid']}.password"
    assert pw.stat().st_mode & 0o777 == 0o600
    assert pw.read_text().strip() == "fixture-repository-material"
    manifest = (workspace / "manifest.json").read_text()
    assert "fixture-repository-material" not in manifest
    assert "fixture-client-material" not in manifest


def test_recovery_kit_rejects_weak_phrase_and_overwrite(tmp_path, monkeypatch):
    payload = _payload(tmp_path)
    monkeypatch.setattr(recovery_kit, "build_recovery_payload", lambda: payload)
    output = tmp_path / "kit.enc"
    with pytest.raises(recovery_kit.BackupRecoveryKitError, match="12 characters"):
        recovery_kit.export_recovery_kit(output, "short")
    recovery_kit.export_recovery_kit(output, "a sufficiently long recovery phrase")
    with pytest.raises(recovery_kit.BackupRecoveryKitError, match="overwrite"):
        recovery_kit.export_recovery_kit(output, "a sufficiently long recovery phrase")


def test_build_payload_contains_remote_repository_mapping(tmp_path, monkeypatch):
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    run_migrations(conn)
    source = str(uuid.uuid4())
    target = str(uuid.uuid4())
    target_uuid = str(uuid.uuid4())
    job_uuid = str(uuid.uuid4())
    host = ensure_backup_host_identity(tmp_path / "target-host")
    conn.execute(
        """INSERT INTO fleet_nodes(
               node_id,hostname,role,main_user,main_uid,main_gid,membership_state
           ) VALUES(?,?,?,?,?,?,?)""",
        (source, "source", "worker", "user", 1000, 1000, "active"),
    )
    conn.execute(
        """INSERT INTO fleet_nodes(
               node_id,hostname,role,main_user,main_uid,main_gid,membership_state
           ) VALUES(?,?,?,?,?,?,?)""",
        (target, "target", "worker", "targetuser", 1000, 1000, "active"),
    )
    conn.execute(
        """INSERT INTO backup_targets(
               target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,
               repository_root,repository_relative_path)
           VALUES(?,?,?,?,?,?,?)""",
        (
            target_uuid, "Drive", target, "local_storage", "disk-uuid",
            "/mnt/drive/LatticeBackups", "LatticeBackups",
        ),
    )
    target_id = conn.execute("SELECT id FROM backup_targets").fetchone()[0]
    conn.execute(
        "INSERT INTO backup_jobs(job_uuid,source_node_id,target_id,source_path) VALUES(?,?,?,?)",
        (job_uuid, source, target_id, "/home/user"),
    )
    conn.execute(
        "INSERT INTO peer_routes(node_id,ip,interface_name,route_kind,last_seen_at,last_success_at) "
        "VALUES(?,?,?,'wifi',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        (target, "10.77.0.20", "wlan0"),
    )
    conn.execute(
        "INSERT INTO peer_routes(node_id,ip,interface_name,route_kind,last_seen_at,last_success_at) "
        "VALUES(?,?,?,'unknown',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        (target, "172.17.0.1", "docker0"),
    )
    conn.execute(
        "INSERT INTO peer_routes(node_id,ip,interface_name,route_kind,last_seen_at,last_success_at) "
        "VALUES(?,?,?,'unknown',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
        (target, "10.2.0.2", "proton-canada"),
    )
    conn.execute(
        "INSERT INTO peer_routes(node_id,ip,interface_name,route_kind,last_seen_at,last_success_at) "
        "VALUES(?,?,?,'wifi',?,?)",
        (target, "10.77.0.95", "wlan0", "2020-01-01 00:00:00", "2020-01-01 00:00:00"),
    )
    conn.commit()
    conn.close()

    source_key = ensure_backup_host_identity(tmp_path / "source-client-fixture")
    ssh_dir = tmp_path / "backup-ssh"
    ssh_dir.mkdir()
    (ssh_dir / "client_ed25519.pub").write_text(source_key.public_key_text)
    monkeypatch.setattr(recovery_kit, "DEFAULT_BACKUP_SSH_DIR", ssh_dir)
    monkeypatch.setattr(recovery_kit, "DEFAULT_CREDENTIAL_ROOT", tmp_path / "credentials")
    monkeypatch.setattr(recovery_kit.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        recovery_kit,
        "load_node_identity",
        lambda: SimpleNamespace(node_id=source, hostname="source", main_user="user"),
    )
    monkeypatch.setattr(recovery_kit, "validate_password_file", lambda path: path)

    def fixture_material(path, maximum=65536):
        if Path(path).name == "client_ed25519":
            return "fixture-client-material\n"
        if Path(path).name == f"{job_uuid}.password":
            return "fixture-repository-material\n"
        raise AssertionError(path)

    monkeypatch.setattr(recovery_kit, "_safe_root_secret", fixture_material)
    monkeypatch.setattr(
        recovery_kit,
        "get_cached_signed_backup_assignment",
        lambda: (
            {
                "schema_version": 1,
                "fleet_id": str(uuid.uuid4()),
                "generation": 1,
                "assignments": [{
                    "source_node_id": source,
                    "target_node_id": target,
                    "target_uuid": target_uuid,
                    "repository_id": job_uuid,
                    "backup_public_key": source_key.public_key_text,
                    "backup_host_public_key": host.public_key_text,
                    "backup_host_key_fingerprint": host.fingerprint,
                }],
            },
            "verified-signature",
        ),
    )
    payload = recovery_kit.build_recovery_payload()
    job = payload["jobs"][0]
    assert job["job_uuid"] == job_uuid
    assert job["target_uuid"] == target_uuid
    assert job["filesystem_uuid"] == "disk-uuid"
    assert job["sftp_port"] == 22024
    assert job["known_routes"] == ["10.77.0.20"]
    assert job["target_host_public_key"] == host.public_key_text
    assert job["restic_password"] == "fixture-repository-material"
