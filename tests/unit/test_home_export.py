from types import SimpleNamespace
import stat

import pytest

from lattice.file_access import home_export


def test_home_bind_health_requires_exact_mount_and_same_home_identity(monkeypatch):
    identity = SimpleNamespace(main_user="workeruser", main_uid=1000, main_gid=1000)
    source = SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=8, st_ino=42))
    target = SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=8, st_ino=42))

    monkeypatch.setattr(home_export, "identity_home", lambda value: source)
    monkeypatch.setattr(
        home_export,
        "exact_mount_source",
        lambda value, mountinfo_path=home_export.MOUNTINFO_PATH: "/dev/root",
    )
    assert home_export.home_bind_is_current(identity, target=target)

    target_bad = SimpleNamespace(stat=lambda: SimpleNamespace(st_dev=8, st_ino=99))
    assert not home_export.home_bind_is_current(identity, target=target_bad)

    monkeypatch.setattr(
        home_export,
        "exact_mount_source",
        lambda value, mountinfo_path=home_export.MOUNTINFO_PATH: None,
    )
    assert not home_export.home_bind_is_current(identity, target=target)


class _FakePath:
    def __init__(self, text, *, dev=8, ino=42, uid=0, mode=None):
        self.text = text
        self.dev = dev
        self.ino = ino
        self.uid = uid
        self.mode = mode if mode is not None else (stat.S_IFDIR | 0o755)

    def __str__(self):
        return self.text

    def stat(self):
        return SimpleNamespace(st_dev=self.dev, st_ino=self.ino, st_uid=self.uid)

    def lstat(self):
        return SimpleNamespace(st_mode=self.mode, st_uid=self.uid)

    def is_symlink(self):
        return False


def test_root_home_export_repair_binds_missing_expected_home(monkeypatch):
    source = _FakePath("/home/workeruser")
    target = _FakePath("/srv/lattice-file-root/Home")
    mount_checks = iter([None, "/dev/root"])
    calls = []

    monkeypatch.setattr(home_export.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        home_export,
        "exact_mount_source",
        lambda value, mountinfo_path=home_export.MOUNTINFO_PATH: next(mount_checks),
    )

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    assert home_export.ensure_home_bind(source=source, target=target, runner=runner)
    assert calls == [[
        "/usr/bin/mount", "--bind", "/home/workeruser", "/srv/lattice-file-root/Home"
    ]]


def test_root_home_export_repair_refuses_foreign_mount(monkeypatch):
    source = _FakePath("/home/workeruser", ino=42)
    target = _FakePath("/srv/lattice-file-root/Home", ino=99)
    monkeypatch.setattr(home_export.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        home_export,
        "exact_mount_source",
        lambda value, mountinfo_path=home_export.MOUNTINFO_PATH: "/unexpected",
    )
    with pytest.raises(home_export.FileHomeExportError, match="different mount"):
        home_export.ensure_home_bind(source=source, target=target)


def test_file_sshd_repairs_home_export_before_start():
    service = open("deploy/systemd/lattice-file-sshd.service", encoding="utf-8").read()
    repair = "ExecStartPre=/opt/lattice/venv/bin/python -m lattice.file_access.home_export"
    validate = "ExecStartPre=/usr/sbin/sshd -t -f /etc/lattice/file-ssh/sshd_config"
    assert repair in service
    assert service.index(repair) < service.index(validate)
