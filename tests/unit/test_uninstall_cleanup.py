from pathlib import Path
from types import SimpleNamespace

import pytest

from lattice.file_access import uninstall_cleanup as cleanup


def test_detach_peer_mounts_only_unmounts_lattice_owned(monkeypatch, tmp_path):
    root = tmp_path / "lattice"
    root.mkdir()
    peer = root / "11111111-1111-4111-8111-111111111111"
    peer.mkdir()
    monkeypatch.setattr(cleanup, "MOUNT_ROOT", root)
    states = ["mounted", "clear"]
    monkeypatch.setattr(cleanup, "_mountinfo", lambda: states[0])
    monkeypatch.setattr(cleanup, "find_mount_entry", lambda path, text: None if text == "clear" else SimpleNamespace(mount_point=str(path.absolute()), filesystem_type="fuse.sshfs", source="user@10.0.0.2:/Home"))
    monkeypatch.setattr(cleanup, "is_lattice_sshfs_mount", lambda *a, **k: True)
    calls = []
    def run(command):
        calls.append(command)
        states[0] = "clear"
    monkeypatch.setattr(cleanup, "_run", run)
    assert cleanup.detach_peer_mounts() == 1
    assert calls == [[cleanup.FUSERMOUNT_BINARY, "-u", str(peer)]]


def test_detach_peer_mounts_refuses_foreign_mount(monkeypatch, tmp_path):
    root = tmp_path / "lattice"
    root.mkdir()
    peer = root / "11111111-1111-4111-8111-111111111111"
    peer.mkdir()
    monkeypatch.setattr(cleanup, "MOUNT_ROOT", root)
    monkeypatch.setattr(cleanup, "_mountinfo", lambda: "mounted")
    monkeypatch.setattr(cleanup, "find_mount_entry", lambda *a: SimpleNamespace())
    monkeypatch.setattr(cleanup, "is_lattice_sshfs_mount", lambda *a, **k: False)
    with pytest.raises(cleanup.UninstallCleanupError, match="non-Lattice"):
        cleanup.detach_peer_mounts()


def test_detach_home_bind_verifies_it_is_gone(monkeypatch):
    states = ["device", None, None]
    monkeypatch.setattr(cleanup, "_exact_mount_source", lambda path: states.pop(0))
    calls = []
    monkeypatch.setattr(cleanup, "_run", lambda command: calls.append(command))
    assert cleanup.detach_home_bind() is True
    assert calls == [["/usr/bin/umount", str(cleanup.HOME_TARGET)]]


def test_detach_home_bind_uses_lazy_unmount_when_verified_bind_is_busy(monkeypatch):
    states = ["device", None, None]
    monkeypatch.setattr(cleanup, "_exact_mount_source", lambda path: states.pop(0))

    calls = []

    def run(command):
        calls.append(command)
        if command == ["/usr/bin/umount", str(cleanup.HOME_TARGET)]:
            raise cleanup.UninstallCleanupError(
                f"/usr/bin/umount {cleanup.HOME_TARGET}: target is busy"
            )

    monkeypatch.setattr(cleanup, "_run", run)

    assert cleanup.detach_home_bind() is True
    assert calls == [
        ["/usr/bin/umount", str(cleanup.HOME_TARGET)],
        ["/usr/bin/umount", "-l", str(cleanup.HOME_TARGET)],
    ]

def test_detach_home_bind_drains_stacked_mount_layers(monkeypatch):
    states = ["ecryptfs", "device", None, None]
    monkeypatch.setattr(
        cleanup,
        "_exact_mount_source",
        lambda path: states.pop(0),
    )

    calls = []
    monkeypatch.setattr(
        cleanup,
        "_run",
        lambda command: calls.append(command),
    )

    assert cleanup.detach_home_bind() is True
    assert calls == [
        ["/usr/bin/umount", str(cleanup.HOME_TARGET)],
        ["/usr/bin/umount", str(cleanup.HOME_TARGET)],
    ]


def test_detach_home_bind_fails_closed_if_layers_never_clear(monkeypatch):
    monkeypatch.setattr(
        cleanup,
        "_exact_mount_source",
        lambda path: "still-mounted",
    )

    calls = []
    monkeypatch.setattr(
        cleanup,
        "_run",
        lambda command: calls.append(command),
    )

    with pytest.raises(
        cleanup.UninstallCleanupError,
        match="still has mounts",
    ):
        cleanup.detach_home_bind()

    assert len(calls) == cleanup.MAX_HOME_UNMOUNT_LAYERS


def test_detach_backup_binds_only_uses_managed_account_shape(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "backup-chroot"
    managed = root / "lattice-bkp-1234567890abcdef1234"
    foreign = root / "not-lattice"
    (managed / "repo").mkdir(parents=True)
    (foreign / "repo").mkdir(parents=True)
    monkeypatch.setattr(cleanup, "BACKUP_CHROOT_ROOT", root)
    states = {managed / "repo": "mounted", foreign / "repo": "mounted"}
    monkeypatch.setattr(
        cleanup,
        "_exact_mount_source",
        lambda path: states.get(path),
    )
    calls = []

    def run(command):
        calls.append(command)
        states[managed / "repo"] = None

    monkeypatch.setattr(cleanup, "_run", run)
    assert cleanup.detach_backup_binds() == 1
    assert calls == [["/usr/bin/umount", str(managed / "repo")]]
