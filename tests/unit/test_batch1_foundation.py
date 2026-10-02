"""Regression tests for Batch 1 clean-install and privilege-boundary fixes."""

from pathlib import Path

import pytest

from lattice.core.crypto.ssh import ensure_lattice_ssh_key
from lattice.onboarding import PairingError, _install_pairing_credentials
from lattice.wizard import journal


def test_installer_installs_one_shared_runtime_environment() -> None:
    environment = Path("deploy/lattice.environment").read_text()
    installer = Path("deploy/install.sh").read_text()

    assert "LATTICE_CONFIG_PATH=/etc/lattice/lattice.toml" in environment
    assert "LATTICE_DB_PATH=/var/lib/lattice/state.sqlite" in environment
    assert "LATTICE_SOCKET_PATH=/run/lattice/master.sock" in environment
    assert '"$SCRIPT_DIR/lattice.environment" /etc/lattice/environment' in installer
    # Installation is now built in a permanent versioned release
    # before /opt/lattice is atomically switched to it.
    assert 'RELEASES_ROOT="/opt/lattice-releases"' in installer
    assert 'RELEASE_ROOT="$RELEASES_ROOT/$RELEASE_ID"' in installer
    assert 'VENV_DIR="$RELEASE_ROOT/venv"' in installer
    assert 'find "$RELEASE_ROOT" -type d' in installer
    assert 'find "$RELEASE_ROOT" -type f' in installer
    assert 'mv -Tf "$TEMP_LINK" "$INSTALL_ROOT"' in installer


def test_master_console_entry_point_exists() -> None:
    from lattice.daemon.main import main

    assert callable(main)


def test_master_daemon_imports_systemd_notifier() -> None:
    source = Path("lattice/daemon/main.py").read_text()
    assert "import sdnotify" in source


def test_production_pairing_fails_closed_without_root_approval(monkeypatch) -> None:
    monkeypatch.delenv("LATTICE_PAIRING_TEST_DIRECT", raising=False)

    with pytest.raises(PairingError, match="root-approved"):
        _install_pairing_credentials({})


def test_network_assignment_uses_a_root_owned_systemd_service() -> None:
    worker = Path("lattice/ip_change/worker_assignment.py").read_text()
    service = Path("deploy/systemd/lattice-network-assignment.service").read_text()
    path_unit = Path("deploy/systemd/lattice-network-assignment.path").read_text()

    assert '"sudo", "-n"' not in worker
    assert "User=root" in service
    assert "lattice-network-exec /var/lib/lattice/network-assignment-request.json" in service
    assert "PathExists=/var/lib/lattice/network-assignment-request.json" in path_unit


def test_incomplete_ssh_keypair_is_not_silently_replaced(tmp_path) -> None:
    (tmp_path / "lattice_ed25519").write_text("private")

    with pytest.raises(RuntimeError, match="incomplete"):
        ensure_lattice_ssh_key(ssh_dir=tmp_path)


def test_wizard_journal_refuses_an_insecure_parent(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(journal, "JOURNAL_PATH", tmp_path / "wizard-journal.json")

    with pytest.raises(PermissionError, match="root-private"):
        journal.save_journal(1, {})


def test_wizard_journal_ignores_an_old_setup_order(monkeypatch, tmp_path) -> None:
    journal_path = tmp_path / "wizard-journal.json"
    journal_path.touch()
    monkeypatch.setattr(journal, "JOURNAL_PATH", journal_path)
    monkeypatch.setattr(
        journal,
        "_read_secure_json",
        lambda _path: {"step": 8, "data": {"role": "worker"}},
    )

    assert journal.load_journal() is None


def test_legacy_broad_sudo_bootstrap_is_removed() -> None:
    cli = Path("lattice/cli/main.py").read_text()
    installer = Path("deploy/install.sh").read_text()
    assert 'commands.bootstrap' not in cli
    assert 'add_parser("bootstrap"' not in cli
    assert not Path("lattice/cli/commands/bootstrap.py").exists()
    assert "lattice-*-nopasswd" in installer
    assert "/usr/bin/systemctl\n" not in installer


def test_installer_uses_hashed_dependency_locks() -> None:
    installer = Path("deploy/install.sh").read_text()
    assert '"$RELEASE_ROOT/requirements.lock"' in installer
    assert installer.count("--require-hashes") >= 2
    assert '"$RELEASE_ROOT/requirements-build.lock"' in installer
    # Production installs the staged release as a normal wheel/package before
    # /opt/lattice is atomically activated. Editable mode is development-only.
    assert "--no-deps" in installer
    assert "--no-build-isolation" in installer
    assert '    "$RELEASE_ROOT" \\' in installer
    assert '-e "$RELEASE_ROOT"' not in installer
    assert "--editable" not in installer
    assert "install --upgrade pip" not in installer
    assert 'install -e "$INSTALL_ROOT[all]"' not in installer
    assert Path("scripts/audit-dependencies.sh").exists()
    assert Path("scripts/refresh-dependency-locks.sh").exists()


def test_production_master_ssh_private_key_is_daemon_owned_and_openssh_safe(tmp_path, monkeypatch):
    from lattice.core.crypto import ssh as ssh_module

    private_key = tmp_path / "lattice_ed25519"
    public_key = tmp_path / "lattice_ed25519.pub"
    private_key.write_text("private")
    public_key.write_text("public")

    class Group:
        gr_gid = 997

    class User:
        pw_uid = 996

    chowns = []
    monkeypatch.setattr(ssh_module.grp, "getgrnam", lambda _name: Group())
    monkeypatch.setattr(ssh_module.pwd, "getpwnam", lambda _name: User())
    monkeypatch.setattr(ssh_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ssh_module.os, "chown", lambda path, uid, gid: chowns.append((Path(path), uid, gid)))

    ssh_module.ensure_lattice_ssh_key(ssh_dir=tmp_path)

    assert private_key.stat().st_mode & 0o777 == 0o600
    assert public_key.stat().st_mode & 0o777 == 0o644
    assert (private_key, 996, 997) in chowns


def test_transport_managers_keep_etc_read_only_except_exact_key_roots():
    mount_unit = Path("deploy/systemd/lattice-mount-manager.service").read_text()
    shell_unit = Path("deploy/systemd/lattice-shell-connection-manager.service").read_text()
    installer = Path("deploy/install.sh").read_text()

    # The mount manager must share the host mount namespace so SSHFS
    # mounts are visible outside the service. Other managers stay sandboxed.
    assert "PrivateMounts=no" in mount_unit
    assert "PrivateTmp=no" in mount_unit
    assert "ProtectSystem=no" in mount_unit
    assert "ProtectKernelTunables=no" in mount_unit
    assert "ProtectKernelModules=no" in mount_unit
    assert "ProtectControlGroups=no" in mount_unit
    assert "ReadWritePaths=" not in mount_unit
    assert "ProtectSystem=full" in shell_unit
    assert "ReadWritePaths=/etc/lattice/shell-ssh" in shell_unit
    assert "ReadWritePaths=/etc/ssh/ssh_config.d" in shell_unit
    assert "ReadWritePaths=/etc/sudoers.d" in shell_unit
    assert "install -d -m 0700 -o root -g root /etc/lattice/file-ssh" in installer
    assert "install -d -m 0700 -o root -g root /etc/lattice/shell-ssh" in installer


def test_worker_heartbeat_does_not_shadow_applied_generation_reader():
    heartbeat = Path("lattice/worker/heartbeat.py").read_text()
    assert "applied_generation = fleet_generation" not in heartbeat
    assert "effective_fleet_generation = fleet_generation" in heartbeat


def test_daemon_sandboxes_allow_netlink_for_ip_monitor():
    master = Path("deploy/systemd/lattice-master.service").read_text()
    worker = Path("deploy/systemd/lattice-worker.service").read_text()
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in master
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in worker


def test_worker_sandbox_can_verify_home_export_without_write_access():
    worker = Path("deploy/systemd/lattice-worker.service").read_text()
    assert "ProtectHome=read-only" in worker.splitlines()
    assert "ProtectHome=yes" not in worker.splitlines()


def test_worker_health_children_do_not_inherit_systemd_notify_socket():
    health = Path("lattice/worker/health.py").read_text()
    assert 'child_env.pop("NOTIFY_SOCKET", None)' in health
    assert "env=child_env" in health
