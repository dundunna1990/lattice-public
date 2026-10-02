from pathlib import Path
from types import SimpleNamespace
import json

import pytest

from lattice.backup import transport_apply
from lattice.backup.transport import BackupTransportAccount
from lattice.backup.transport_plan import PlannedBackupRepository


def test_default_authorized_keys_path_is_outside_restricted_lattice_tree():
    from lattice.backup.transport import DEFAULT_AUTHORIZED_KEYS_DIR
    assert DEFAULT_AUTHORIZED_KEYS_DIR == Path("/etc/lattice-backup-authorized-keys")


def _patch_root(tmp_path, monkeypatch):
    request = tmp_path / "request.json"
    ssh_dir = tmp_path / "backup-ssh"
    auth_dir = ssh_dir / "authorized_keys"
    chroot = tmp_path / "chroot"
    monkeypatch.setattr(transport_apply, "REQUEST_PATH", request)
    monkeypatch.setattr(
        transport_apply,
        "DESIRED_STATE_PATH",
        tmp_path / "backup-transport-desired.json",
    )
    monkeypatch.setattr(transport_apply, "SSHD_CONFIG", ssh_dir / "sshd_config")
    monkeypatch.setattr(transport_apply, "DEFAULT_BACKUP_SSH_DIR", ssh_dir)
    monkeypatch.setattr(transport_apply, "DEFAULT_AUTHORIZED_KEYS_DIR", auth_dir)
    monkeypatch.setattr(transport_apply, "DEFAULT_CHROOT_ROOT", chroot)
    monkeypatch.setattr(
        transport_apply,
        "BACKUP_APPLIED_PATH",
        tmp_path / "backup-transport-applied.json",
    )
    monkeypatch.setattr(transport_apply.os, "geteuid", lambda: 0)
    monkeypatch.setattr(transport_apply.os, "chown", lambda *args, **kwargs: None)
    lattice = SimpleNamespace(
        pw_uid=__import__("os").getuid(), pw_gid=__import__("os").getgid(), pw_dir="/var/lib/lattice",
        pw_shell="/usr/sbin/nologin",
    )
    backup_user = SimpleNamespace(
        pw_uid=901, pw_gid=901, pw_dir="/",
        pw_shell="/usr/sbin/nologin",
    )
    monkeypatch.setattr(
        transport_apply.pwd,
        "getpwnam",
        lambda name: lattice if name == "lattice" else backup_user,
    )
    monkeypatch.setattr(
        transport_apply,
        "load_node_identity",
        lambda: SimpleNamespace(
            node_id="11111111-1111-4111-8111-111111111111"
        ),
    )
    monkeypatch.setattr(
        transport_apply,
        "ensure_backup_host_identity",
        lambda _directory: SimpleNamespace(
            public_key_text=(
                "ssh-ed25519 "
                "AAAAC3NzaC1lZDI1NTE5AAAAIK5OUh/pfTg0ROo2R8A8mb5Y8xYw2yLdBpAsRmArJ/0+ test"
            )
        ),
    )
    monkeypatch.setattr(
        transport_apply,
        "_trusted_signing_key",
        lambda: "ignored",
    )
    request.write_text(json.dumps({
        "assignment": {
            "schema_version": 1,
            "fleet_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "generation": 1,
            "assignments": [],
        },
        "signature": "sig",
    }))
    request.chmod(0o600)
    return request, backup_user


def test_apply_rejects_nonfixed_request_path(tmp_path, monkeypatch):
    _patch_root(tmp_path, monkeypatch)
    with pytest.raises(
        transport_apply.BackupTransportApplyError,
        match="fixed",
    ):
        transport_apply.apply_request(tmp_path / "other.json")


def test_apply_builds_one_source_only_chroot(tmp_path, monkeypatch):
    request, _ = _patch_root(tmp_path, monkeypatch)
    source = "22222222-2222-4222-8222-222222222222"
    target_uuid = "33333333-3333-4333-8333-333333333333"
    account = BackupTransportAccount(
        source,
        target_uuid,
        (
            "ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAICUKU8juOpHYpC7Wi4nR4fATgOd/9yEoqVsrpySLzYCY source"
        ),
    )
    repo = tmp_path / "drive" / "LatticeBackups" / source
    plan = PlannedBackupRepository(
        source,
        target_uuid,
        "44444444-4444-4444-8444-444444444444",
        repo,
        account,
    )
    monkeypatch.setattr(
        transport_apply,
        "build_local_transport_plan",
        lambda *args, **kwargs: [plan],
    )
    monkeypatch.setattr(
        transport_apply,
        "exact_mount_source",
        lambda _path: None,
    )
    binds = []
    monkeypatch.setattr(
        transport_apply,
        "_ensure_bind",
        lambda source, target, **kwargs: binds.append((source, target)),
    )

    assert transport_apply.apply_request(request) == 1
    username = plan.username
    assert binds == [
        (
            repo,
            transport_apply.DEFAULT_CHROOT_ROOT / username / "repo",
        )
    ]
    assert repo.stat().st_mode & 0o777 == 0o700
    config = transport_apply.SSHD_CONFIG.read_text()
    assert f"AllowUsers {username}" in config
    assert (
        f"ChrootDirectory {transport_apply.DEFAULT_CHROOT_ROOT}/{username}"
        in config
    )
    key_file = transport_apply.DEFAULT_AUTHORIZED_KEYS_DIR / username
    assert key_file.read_text().startswith("restrict ssh-ed25519 ")
    assert request.exists()
    generation = transport_apply.finalize_request(request)
    assert generation == 1
    assert not request.exists()


def test_apply_with_no_local_assignments_removes_listener_config(
    tmp_path,
    monkeypatch,
):
    request, _ = _patch_root(tmp_path, monkeypatch)
    transport_apply.SSHD_CONFIG.parent.mkdir(parents=True)
    transport_apply.SSHD_CONFIG.write_text("old")
    monkeypatch.setattr(
        transport_apply,
        "build_local_transport_plan",
        lambda *args, **kwargs: [],
    )
    assert transport_apply.apply_request(request) == 0
    assert not transport_apply.SSHD_CONFIG.exists()
    assert request.exists()
    transport_apply.finalize_request(request)
    assert not request.exists()
