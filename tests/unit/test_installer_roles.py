"""Checks that installation cannot start both runtime roles."""
from pathlib import Path


def test_installer_defers_role_startup_to_guided_setup():
    installer = Path("deploy/install.sh").read_text()
    assert "systemctl enable lattice-master.service" not in installer
    assert "systemctl enable lattice-worker.service" not in installer
    assert "No master or worker service has been started" in installer


def test_worker_unit_uses_only_narrow_root_helpers():
    installer = Path("deploy/install.sh").read_text()
    assert "lattice-action-exec restart lattice-worker.service" in installer
    assert "lattice-action-exec status lattice-worker.service" in installer
    assert "lattice-pairing-exec /var/lib/lattice/pairing-install-request.json" not in installer
    assert "lattice-network-exec /var/lib/lattice/network-assignment-request.json" not in installer
    assert "NOPASSWD: ALL" not in installer


def test_setup_enables_boot_recovery_before_starting_a_role():
    lifecycle = Path("lattice/wizard/lifecycle.py").read_text()
    recovery_position = lifecycle.index(
        '["systemctl", "enable", "lattice-boot-recovery.service"]'
    )
    role_position = lifecycle.index(
        '["systemctl", "enable", "--now", role_service]'
    )
    assert recovery_position < role_position

    recovery_unit = Path("deploy/systemd/lattice-boot-recovery.service").read_text()
    assert "[Install]" in recovery_unit
    assert "WantedBy=multi-user.target" in recovery_unit


def test_daemons_can_read_the_generated_config_without_making_it_public():
    wizard = Path("lattice/wizard/orchestration.py").read_text()
    assert 'os.chmod(config_path, 0o640)' in wizard
    assert 'os.chown(config_path, 0, grp.getgrnam("lattice").gr_gid)' in wizard


def test_firewall_is_changed_only_during_guided_ssh_setup_not_normal_worker_runtime():
    wizard = Path("lattice/wizard/orchestration.py").read_text()
    worker_api = Path("lattice/daemon/api/worker_app.py").read_text()
    assert "ensure_local_lan_ssh_firewall()" in wizard
    assert "configure_ufw_for_worker" not in worker_api


def test_master_setup_enables_its_alert_only_self_check_timer():
    lifecycle = Path("lattice/wizard/lifecycle.py").read_text()
    assert '"lattice-health-watchdog.timer"' in lifecycle


def test_runtime_init_hard_requires_successful_boot_recovery():
    unit = Path(
        "deploy/systemd/lattice-init.service"
    ).read_text()

    assert (
        "Requires=lattice-boot-recovery.service"
        in unit
    )
    assert (
        "After=network-online.target "
        "lattice-boot-recovery.service"
        in unit
    )


def test_installer_builds_versioned_release_before_activation():
    installer = Path(
        "deploy/install.sh"
    ).read_text()

    assert (
        'RELEASES_ROOT="/opt/lattice-releases"'
        in installer
    )
    assert (
        'RELEASE_ROOT="$RELEASES_ROOT/$RELEASE_ID"'
        in installer
    )

    stage_position = installer.index(
        'rsync -a --delete'
    )
    validate_position = installer.index(
        '"$VENV_DIR/bin/lattice" --version'
    )
    activate_position = installer.index(
        'mv -Tf "$TEMP_LINK" "$INSTALL_ROOT"'
    )

    assert stage_position < validate_position
    assert validate_position < activate_position


def test_installer_has_post_activation_rollback():
    installer = Path(
        "deploy/install.sh"
    ).read_text()

    assert "rollback_install()" in installer
    # ERR preserves the real command failure, while signals use their
    # conventional shell exit statuses.
    assert (
        "trap 'rollback_install $?' ERR"
        in installer
    )
    assert (
        "trap 'rollback_install 130' INT"
        in installer
    )
    assert (
        "trap 'rollback_install 143' TERM"
        in installer
    )
    assert (
        'PREVIOUS_LINK="$(readlink -f "$INSTALL_ROOT")"'
        in installer
    )
    assert (
        'mv "$INSTALL_ROOT" "$PREVIOUS_DIRECTORY"'
        in installer
    )
    assert "trap - ERR INT TERM" in installer


def test_worker_root_helpers_cannot_conflict_master_service():
    for filename in (
        "deploy/systemd/lattice-network-assignment.service",
        "deploy/systemd/lattice-credential-revoke.service",
    ):
        unit = Path(filename).read_text()

        assert (
            "ExecCondition=/usr/bin/grep -qx worker "
            "/etc/lattice/role"
            in unit
        )

        assert (
            "Conflicts=lattice-master.service"
            not in unit
        )


def test_installer_rolls_back_external_integration_files():
    installer = Path(
        "deploy/install.sh"
    ).read_text()

    assert "snapshot_install_integration()" in installer
    assert "restore_install_integration()" in installer

    for path in (
        "/etc/lattice/environment",
        "/etc/tmpfiles.d/lattice.conf",
        "/etc/sysusers.d/lattice.conf",
        "/etc/sudoers.d/lattice-action-exec",
        "/etc/logrotate.d/lattice",
    ):
        assert path in installer

    assert (
        "find /etc/systemd/system"
        in installer
    )
    assert (
        "systemctl daemon-reload"
        in installer
    )


def test_installer_has_explicit_signal_rollback_and_removes_failed_release():
    installer = Path(
        "deploy/install.sh"
    ).read_text()

    assert (
        "trap 'rollback_install 130' INT"
        in installer
    )
    assert (
        "trap 'rollback_install 143' TERM"
        in installer
    )
    assert (
        'rm -rf -- "$RELEASE_ROOT"'
        in installer
    )


def test_upgrade_removes_obsolete_master_socket():
    installer = Path(
        "deploy/install.sh"
    ).read_text()

    assert (
        "systemctl disable --now "
        "lattice-master.socket"
        in installer
    )
    assert (
        "rm -f /etc/systemd/system/"
        "lattice-master.socket"
        in installer
    )


def test_installer_pins_and_verifies_restic_release():
    installer = Path('deploy/install.sh').read_text()
    assert 'RESTIC_VERSION="0.19.1"' in installer
    assert 'RESTIC_SHA256_AMD64="f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"' in installer
    assert 'RESTIC_SHA256_ARM64="a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465"' in installer
    assert 'sha256sum "$archive"' in installer
    assert 'if [[ "$actual" != "$expected" ]]' in installer
    assert 'restic_${RESTIC_VERSION}_linux_${upstream_arch}.bz2' in installer
    assert 'if ! "$destination" version | grep -Fq "restic ${RESTIC_VERSION} "; then' in installer


def test_installer_restic_architecture_allowlist_is_fail_closed():
    installer = Path('deploy/install.sh').read_text()
    assert 'amd64) upstream_arch="amd64"' in installer
    assert 'arm64) upstream_arch="arm64"' in installer
    assert 'does not yet provide a pinned Restic build for architecture' in installer
    assert 'curl --fail --location --silent --show-error' in installer
    assert "--proto '=https' --tlsv1.2" in installer


def test_upgrade_converges_required_backup_units_for_existing_role():
    installer = Path('deploy/install.sh').read_text()
    assert 'converge_existing_backup_units()' in installer
    assert '[[ "$HAD_EXISTING_INSTALL" -eq 1 ]] || return 0' in installer
    assert '[[ -f /etc/lattice/role ]] || return 0' in installer
    for unit in (
        'lattice-backup.timer',
        'lattice-backup-maintenance.timer',
        'lattice-backup-run-request.path',
        'lattice-backup-query.path',
        'lattice-backup-restore.path',
        'lattice-backup-transport-reconcile.path',
        'lattice-backup-sshd.service',
    ):
        assert unit in installer
    assert 'lattice-backup-alerts.timer' in installer
    assert 'lattice-backup-observation-refresh.timer' in installer
    assert 'lattice-backup-assignment-reconcile.timer' in installer
    assert 'if [[ "$role" == "master" ]]' in installer
    assert 'systemctl enable --now "$unit"' in installer
    assert installer.index('restart_installed_runtime_services') < installer.index('converge_existing_backup_units')


def test_fresh_install_still_does_not_auto_select_role_for_backup_convergence():
    installer = Path('deploy/install.sh').read_text()
    block = installer[installer.index('converge_existing_backup_units()'):installer.index('prune_old_releases()')]
    assert '[[ "$HAD_EXISTING_INSTALL" -eq 1 ]] || return 0' in block
    assert '[[ -f /etc/lattice/role ]] || return 0' in block


def test_backup_python_services_that_need_db_load_runtime_environment():
    required = [
        "lattice-backup-assignment-reconcile.service",
        "lattice-backup-maintenance.service",
        "lattice-backup-transport-reconcile.service",
        "lattice-backup-alerts.service",
        "lattice-backup-observation-refresh.service",
        "lattice-backup-query.service",
        "lattice-backup-restore.service",
        "lattice-backup-run-request.service",
        "lattice-backup.service",
    ]
    for name in required:
        unit = Path("deploy/systemd") / name
        text = unit.read_text()
        assert "EnvironmentFile=-/etc/lattice/environment" in text, name


def test_backup_remote_route_services_allow_netlink_introspection():
    required = [
        "lattice-backup-query.service",
        "lattice-backup-restore.service",
        "lattice-backup-run-request.service",
        "lattice-backup.service",
    ]
    for name in required:
        text = (Path("deploy/systemd") / name).read_text()
        assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in text, name


def test_backup_transport_reconcile_starts_listener_after_first_materialization():
    text = Path("deploy/systemd/lattice-backup-transport-reconcile.service").read_text()
    assert "ExecStartPost=/usr/bin/systemctl restart lattice-backup-sshd.service" in text
    assert "try-restart lattice-backup-sshd.service" not in text
    assert "StartLimitIntervalSec=10min" in text
    assert "StartLimitBurst=3" in text


def test_upgrade_provisions_backup_identity_before_runtime_restart():
    script = Path("deploy/install.sh").read_text()
    assert "ensure_existing_backup_identity()" in script
    assert "from lattice.backup.identity import local_backup_identity" in script
    assert (
        script.index("ensure_existing_backup_identity")
        < script.rindex("restart_installed_runtime_services")
    )
