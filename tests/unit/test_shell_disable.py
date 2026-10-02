from types import SimpleNamespace

from lattice.shell_access import manager, reconcile


def test_disabled_reconcile_removes_only_managed_shell_artifacts(tmp_path, monkeypatch):
    shell_dir = tmp_path / "shell"
    server = tmp_path / "server"
    client = tmp_path / "client"
    ssh_config = tmp_path / "90-lattice-shell.conf"
    sudoers = tmp_path / "lattice-shell-admin"
    monkeypatch.setattr(reconcile, "SHELL_DIR", shell_dir)
    monkeypatch.setattr(reconcile, "SHELL_SERVER_RUNTIME_DIR", server)
    monkeypatch.setattr(reconcile, "SHELL_CLIENT_RUNTIME_DIR", client)
    monkeypatch.setattr(reconcile, "SSH_CONFIG", ssh_config)
    monkeypatch.setattr(reconcile, "SUDOERS", sudoers)
    managed = (
        shell_dir / "authorized_keys",
        shell_dir / "known_hosts",
        shell_dir / "sshd_config",
        server / "authorized_keys",
        client / "client_ed25519",
        client / "known_hosts",
        ssh_config,
        sudoers,
    )
    for path in managed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("managed")
    keep = shell_dir / "host_ed25519"
    keep.write_text("identity")
    monkeypatch.setattr(reconcile.os, "geteuid", lambda: 0)
    monkeypatch.setattr(reconcile, "load_node_identity", lambda: SimpleNamespace(node_id="node"))
    monkeypatch.setattr(
        reconcile,
        "load_config",
        lambda: SimpleNamespace(shell_access=SimpleNamespace(enabled=False)),
    )
    result = reconcile.reconcile_shell_channel()
    assert result["enabled"] is False
    assert result["changed"] is True
    assert keep.read_text() == "identity"
    assert not ssh_config.exists()
    assert not sudoers.exists()


def test_disabled_manager_stops_listener_and_closes_control_sockets(tmp_path, monkeypatch):
    control = tmp_path / "control"
    control.mkdir()
    sock = control / "masteruser-peer.sock"
    sock.write_text("socket-fixture")
    monkeypatch.setattr(manager, "CONTROL_ROOT", control)
    identity = SimpleNamespace(node_id="node", main_user="masteruser")
    monkeypatch.setattr(manager, "load_node_identity", lambda: identity)
    monkeypatch.setattr(manager, "current_role", lambda: "worker")
    monkeypatch.setattr(manager, "ensure_rotation_staged_if_due", lambda: None)
    monkeypatch.setattr(manager, "promote_local_rotation_if_requested", lambda: None)
    monkeypatch.setattr(manager, "cleanup_completed_local_rotation", lambda: None)
    monkeypatch.setattr(manager, "reconcile_shell_channel", lambda: {"enabled": False})
    monkeypatch.setattr(
        manager.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=1000, pw_gid=1000),
    )
    calls = []
    monkeypatch.setattr(
        manager,
        "_run_as",
        lambda uid, gid, argv: calls.append(argv) or SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        manager.subprocess,
        "run",
        lambda argv, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    manager.reconcile_connections()
    assert any(argv[0] == "ssh" and "-O" in argv and "exit" in argv for argv in calls)
    assert not sock.exists()
