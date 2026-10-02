from pathlib import Path
import os
import stat

import pytest

from lattice.file_access.transport_apply import (
    FileTransportApplyError,
    _atomic_write,
    _decode_mount_path,
)


def test_atomic_transport_write_refuses_symlink(
    tmp_path,
):
    target = tmp_path / "target"
    target.write_text("keep\n")

    link = tmp_path / "managed"
    link.symlink_to(target)

    with pytest.raises(
        FileTransportApplyError,
        match="unsafe path",
    ):
        _atomic_write(
            link,
            "replace\n",
            mode=0o600,
            uid=os.getuid(),
            gid=os.getgid(),
        )

    assert target.read_text() == "keep\n"


def test_atomic_transport_write_sets_exact_mode(
    tmp_path,
):
    path = tmp_path / "managed"

    _atomic_write(
        path,
        "hello\n",
        mode=0o640,
        uid=os.getuid(),
        gid=os.getgid(),
    )

    assert path.read_text() == "hello\n"
    assert (
        stat.S_IMODE(
            path.stat().st_mode
        )
        == 0o640
    )


def test_mountinfo_path_decoder():
    assert (
        _decode_mount_path(
            "/home/masteruser/TV\\040Shows"
        )
        == "/home/masteruser/TV Shows"
    )


def test_root_reconciler_rejects_arbitrary_request_path(
    tmp_path,
    monkeypatch,
):
    from lattice.file_access import (
        transport_apply,
    )

    monkeypatch.setattr(
        transport_apply.os,
        "geteuid",
        lambda: 0,
    )

    with pytest.raises(
        FileTransportApplyError,
        match="fixed Lattice",
    ):
        transport_apply.apply_request(
            tmp_path / "attacker.json"
        )


def test_transport_exec_wrapper_is_exact():
    wrapper = Path(
        "deploy/lattice-file-transport-exec"
    ).read_text()

    assert (
        "lattice.file_access.transport_apply"
        in wrapper
    )

    assert "eval " not in wrapper
    assert "bash -c" not in wrapper


def test_transport_reconcile_service_runs_as_root():
    service = Path(
        "deploy/systemd/"
        "lattice-file-transport-reconcile.service"
    ).read_text()

    assert "User=root" in service

    assert (
        "ExecStart=/opt/lattice/bin/"
        "lattice-file-transport-exec"
        in service
    )


def test_transport_reconcile_is_request_driven():
    path_unit = Path(
        "deploy/systemd/"
        "lattice-file-transport-reconcile.path"
    ).read_text()

    assert (
        "PathChanged=/var/lib/lattice/"
        "file-transport-request.json"
        in path_unit
    )

    assert (
        "PathExists=/var/lib/lattice/"
        "file-transport-request.json"
        not in path_unit
    )


def test_installer_installs_transport_helper():
    installer = Path(
        "deploy/install.sh"
    ).read_text()

    assert (
        'lattice-file-transport-exec" '
        '"$INSTALL_ROOT/bin/lattice-file-transport-exec"'
        in installer
    )


def test_reconcile_restarts_file_service_only_after_success():
    service = Path(
        "deploy/systemd/"
        "lattice-file-transport-reconcile.service"
    ).read_text()

    assert (
        "ExecStart=/opt/lattice/bin/"
        "lattice-file-transport-exec"
        in service
    )

    assert (
        "ExecStartPost=/usr/bin/systemctl "
        "--no-block restart lattice-file-sshd.service"
        in service
    )


def test_file_sshd_has_no_reconcile_ordering_cycle():
    service = Path(
        "deploy/systemd/"
        "lattice-file-sshd.service"
    ).read_text()

    assert (
        "After=network.target\n"
        in service
    )

    assert (
        "After=network.target "
        "lattice-file-transport-reconcile.service"
        not in service
    )
