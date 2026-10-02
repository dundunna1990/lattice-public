import pytest
import json
import os
from pathlib import Path
import pwd

from lattice.file_access.desktop import (
    reconcile_desktop,
    remove_desktop_integration,
)
from lattice.file_access.identity import (
    ensure_node_identity,
)


LOCAL_NODE = (
    "11111111-1111-4111-8111-111111111111"
)

REMOTE_NODE = (
    "22222222-2222-4222-8222-222222222222"
)

OFFLINE_NODE = (
    "33333333-3333-4333-8333-333333333333"
)


def _setup_identity(
    tmp_path,
    monkeypatch,
):
    account = pwd.getpwuid(
        os.getuid()
    )

    identity_path = (
        tmp_path
        / "node-identity.json"
    )

    identity = ensure_node_identity(
        account.pw_name,
        path=identity_path,
        main_uid=account.pw_uid,
        main_gid=account.pw_gid,
    )

    payload = json.loads(
        identity_path.read_text()
    )
    payload["node_id"] = LOCAL_NODE
    identity_path.write_text(
        json.dumps(payload)
    )
    identity_path.chmod(
        0o600
    )

    monkeypatch.setenv(
        "LATTICE_NODE_IDENTITY_PATH",
        str(identity_path),
    )

    fake_home = (
        tmp_path / "home"
    )
    fake_home.mkdir()

    desktop = (
        fake_home / "Desktop"
    )
    desktop.mkdir()

    class Account:
        pw_name = account.pw_name
        pw_uid = account.pw_uid
        pw_gid = account.pw_gid
        pw_dir = str(fake_home)

    monkeypatch.setattr(
        "lattice.file_access.desktop."
        "pwd.getpwnam",
        lambda _name: Account(),
    )
    # Most integration tests exercise file ownership/migration independently
    # of the desktop environment metadata backend. Dedicated tests below
    # verify the trusted-launcher call itself.
    monkeypatch.setattr(
        "lattice.file_access.desktop._trust_desktop_launcher",
        lambda _shortcut, _account, _home: None,
    )

    return (
        fake_home,
        desktop,
    )


def _plan(path):
    payload = {
        "generation":
            4,
        "peers":
            [
                {
                    "node_id":
                        REMOTE_NODE,
                    "hostname":
                        "worker-node",
                    "ip":
                        "10.77.0.201",
                    "remote_user":
                        "masteruser",
                    "port":
                        22022,
                }
            ],
        "visible_peers":
            [
                {
                    "node_id":
                        LOCAL_NODE,
                    "hostname":
                        "master-node",
                },
                {
                    "node_id":
                        REMOTE_NODE,
                    "hostname":
                        "worker-node",
                },
                {
                    "node_id":
                        OFFLINE_NODE,
                    "hostname":
                        "backup-node",
                },
            ],
        "retired_node_ids":
            [],
    }

    path.write_text(
        json.dumps(payload)
    )
    path.chmod(0o600)


def test_desktop_shows_offline_peer_without_locator(
    tmp_path,
    monkeypatch,
):
    home, desktop = _setup_identity(
        tmp_path,
        monkeypatch,
    )

    plan = tmp_path / "plan.json"
    _plan(plan)

    mount_root = tmp_path / "mnt"
    mount_root.mkdir()

    application = (
        tmp_path / "lattice.desktop"
    )
    application.write_text(
        "[Desktop Entry]\n"
        "X-Lattice-Managed=true\n"
    )
    application.chmod(0o644)

    state = tmp_path / "state.json"

    result = reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=state,
        application_path=application,
    )

    lattice_home = (
        home / "Lattice"
    )

    assert result["status"] == "ok"

    assert (
        lattice_home
        / "worker-node"
    ).is_symlink()

    # No current IP exists for the backup node, but it remains visible because
    # signed fleet membership, not reachability, controls visibility.
    assert (
        lattice_home
        / "backup-node"
    ).is_symlink()

    assert not (
        lattice_home
        / "master-node"
    ).exists()

    # Application launchers are installed only by deploy/install.sh, not by
    # the file-access reconciler that maintains the Lattice shared folder.
    assert not (desktop / "Lattice Nodes.desktop").exists()


def test_desktop_never_replaces_user_file(
    tmp_path,
    monkeypatch,
):
    home, _desktop = _setup_identity(
        tmp_path,
        monkeypatch,
    )

    plan = tmp_path / "plan.json"
    _plan(plan)

    lattice_home = (
        home / "Lattice"
    )
    lattice_home.mkdir()

    personal = (
        lattice_home
        / "worker-node"
    )
    personal.write_text(
        "user file"
    )

    mount_root = tmp_path / "mnt"
    mount_root.mkdir()

    result = reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=(
            tmp_path / "state.json"
        ),
        application_path=(
            tmp_path
            / "missing.desktop"
        ),
    )

    assert personal.read_text() == (
        "user file"
    )

    assert str(
        personal
    ) in result["conflicts"]


def test_revoked_peer_link_is_removed_safely(
    tmp_path,
    monkeypatch,
):
    home, _desktop = _setup_identity(
        tmp_path,
        monkeypatch,
    )

    plan = tmp_path / "plan.json"
    _plan(plan)

    mount_root = tmp_path / "mnt"
    mount_root.mkdir()

    state = tmp_path / "state.json"

    reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=state,
        application_path=(
            tmp_path
            / "missing.desktop"
        ),
    )

    link = (
        home
        / "Lattice"
        / "backup-node"
    )

    assert link.is_symlink()

    payload = json.loads(
        plan.read_text()
    )

    payload["visible_peers"] = [
        item
        for item in payload[
            "visible_peers"
        ]
        if item[
            "node_id"
        ] != OFFLINE_NODE
    ]

    payload[
        "retired_node_ids"
    ] = [
        OFFLINE_NODE
    ]

    plan.write_text(
        json.dumps(payload)
    )

    reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=state,
        application_path=(
            tmp_path
            / "missing.desktop"
        ),
    )

    assert not link.exists()
    assert not link.is_symlink()


def test_desktop_cleanup_removes_only_managed_links(
    tmp_path,
    monkeypatch,
):
    home, desktop = _setup_identity(
        tmp_path,
        monkeypatch,
    )

    plan = tmp_path / "plan.json"
    _plan(plan)

    mount_root = tmp_path / "mnt"
    mount_root.mkdir()

    application = (
        tmp_path / "lattice.desktop"
    )
    application.write_text(
        "[Desktop Entry]\n"
        "X-Lattice-Managed=true\n"
    )
    application.chmod(0o644)

    state = tmp_path / "state.json"

    reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=state,
        application_path=application,
    )

    personal = (
        home
        / "Lattice"
        / "notes.txt"
    )
    personal.write_text(
        "keep me"
    )

    remove_desktop_integration(
        state_path=state,
        application_path=application,
    )

    assert personal.read_text() == (
        "keep me"
    )

    assert not (
        desktop
        / "Lattice Nodes.desktop"
    ).exists()



def test_desktop_reconcile_does_not_manage_application_launchers(tmp_path, monkeypatch):
    _home, desktop = _setup_identity(tmp_path, monkeypatch)
    plan = tmp_path / "plan.json"
    _plan(plan)
    mount_root = tmp_path / "mnt"
    mount_root.mkdir()
    application = tmp_path / "lattice.desktop"
    application.write_text("[Desktop Entry]\nName=Lattice Nodes\n")
    legacy = desktop / "Lattice.desktop"
    legacy.symlink_to(application)

    reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=tmp_path / "state.json",
        application_path=application,
    )

    # deploy/install.sh owns the two official launchers.  File-access
    # reconciliation must never create, rewrite, or remove desktop apps.
    assert legacy.is_symlink()
    assert not (desktop / "Lattice Nodes.desktop").exists()


def test_desktop_preserves_unmanaged_nodes_launcher(tmp_path, monkeypatch):
    _home, desktop = _setup_identity(tmp_path, monkeypatch)
    plan = tmp_path / "plan.json"
    _plan(plan)
    mount_root = tmp_path / "mnt"
    mount_root.mkdir()
    application = tmp_path / "lattice.desktop"
    application.write_text(
        "[Desktop Entry]\n"
        "Name=Lattice Nodes\n"
        "X-Lattice-Managed=true\n"
    )
    application.chmod(0o644)
    personal = desktop / "Lattice Nodes.desktop"
    personal.write_text("user file\n")

    reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=tmp_path / "state.json",
        application_path=application,
    )

    assert personal.read_text() == "user file\n"

def test_active_mount_target_is_not_chowned_or_chmodded(tmp_path, monkeypatch):
    import lattice.file_access.desktop as desktop

    node_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    mount_root = tmp_path / "mnt"
    target = mount_root / node_id
    target.mkdir(parents=True)

    monkeypatch.setattr(desktop.os.path, "ismount", lambda path: Path(path) == target)
    monkeypatch.setattr(desktop.os, "geteuid", lambda: 0)

    def forbidden(*args, **kwargs):
        raise AssertionError("mounted target metadata must not be mutated")

    monkeypatch.setattr(desktop.os, "chown", forbidden)
    monkeypatch.setattr(desktop.os, "chmod", forbidden)

    assert desktop._ensure_mount_target(node_id, mount_root=mount_root, uid=1000, gid=1000) == target


def test_mount_target_metadata_failure_is_desktop_error(tmp_path, monkeypatch):
    import lattice.file_access.desktop as desktop

    node_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    mount_root = tmp_path / "mnt"
    target = mount_root / node_id
    target.mkdir(parents=True)

    monkeypatch.setattr(desktop.os.path, "ismount", lambda path: False)
    monkeypatch.setattr(desktop.os, "geteuid", lambda: 0)
    monkeypatch.setattr(desktop.os, "chown", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError("denied")))

    with pytest.raises(desktop.DesktopIntegrationError, match="Could not prepare peer mount target"):
        desktop._ensure_mount_target(node_id, mount_root=mount_root, uid=1000, gid=1000)


def test_desktop_reconcile_does_not_create_or_trust_application_launchers(tmp_path, monkeypatch):
    _home, desktop = _setup_identity(tmp_path, monkeypatch)
    plan = tmp_path / "plan.json"
    _plan(plan)
    mount_root = tmp_path / "mnt"
    mount_root.mkdir()
    application = tmp_path / "lattice.desktop"
    application.write_text("[Desktop Entry]\nName=Lattice Nodes\n")
    trusted = []
    monkeypatch.setattr(
        "lattice.file_access.desktop._trust_desktop_launcher",
        lambda shortcut, _account, _home: trusted.append(shortcut),
    )

    reconcile_desktop(
        plan_path=plan,
        mount_root=mount_root,
        state_path=tmp_path / "state.json",
        application_path=application,
    )

    assert trusted == []
    assert not (desktop / "Lattice Nodes.desktop").exists()


def test_trust_desktop_launcher_sets_and_verifies_gio_metadata(tmp_path, monkeypatch):
    import subprocess
    import lattice.file_access.desktop as desktop_module

    account = pwd.getpwuid(os.getuid())
    shortcut = tmp_path / "Lattice Nodes.desktop"
    shortcut.write_text("[Desktop Entry]\n")
    calls = []

    def fake_run(_account, _home, argv):
        calls.append(argv)
        if "info" in argv:
            return subprocess.CompletedProcess(argv, 0, "  metadata::trusted: true\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(desktop_module, "_run_as_main_user", fake_run)
    desktop_module._trust_desktop_launcher(shortcut, account, tmp_path)

    assert calls[0][1:4] == ["set", str(shortcut), "metadata::trusted"]
    assert calls[0][4] == "true"
    assert calls[1][1:4] == ["info", "-a", "metadata::*"]
    assert calls[1][4] == str(shortcut)


def test_disconnected_mount_target_becomes_desktop_error(tmp_path, monkeypatch):
    import errno
    import lattice.file_access.desktop as desktop

    mount_root = tmp_path / "mnt"
    mount_root.mkdir()
    node_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    target = mount_root / node_id
    target.mkdir()

    original_exists = Path.exists

    def disconnected_exists(path):
        if path == target:
            raise OSError(errno.ENOTCONN, "Transport endpoint is not connected")
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", disconnected_exists)

    with pytest.raises(desktop.DesktopIntegrationError, match="inspect peer mount target"):
        desktop._ensure_mount_target(
            node_id, mount_root=mount_root, uid=os.getuid(), gid=os.getgid()
        )
