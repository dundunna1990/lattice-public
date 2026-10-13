"""Fresh-install entrypoint and legacy-flow regression checks."""
from pathlib import Path


def test_installer_provisions_python_build_dependencies():
    installer = Path("deploy/install.sh").read_text()
    assert "python3-dev" in installer
    assert "build-essential" in installer


def test_installer_creates_stable_operator_command_and_rolls_it_back():
    installer = Path("deploy/install.sh").read_text()
    assert 'CLI_LAUNCHER="/usr/local/bin/lattice"' in installer
    assert 'ln -s "$ACTIVE_VENV/bin/lattice" "$CLI_TEMP"' in installer
    assert '/usr/local/bin/lattice' in installer
    assert 'echo "  Continue with: sudo lattice init"' in installer
    # The launcher is part of the external-integration snapshot, so a failed
    # upgrade restores exactly what existed before the attempt.
    assert installer.count("/usr/local/bin/lattice") >= 3


def test_installer_refuses_to_overwrite_foreign_operator_command():
    installer = Path("deploy/install.sh").read_text()
    assert 'is not managed by Lattice' in installer
    assert 'readlink "$CLI_LAUNCHER"' in installer


def test_uninstall_removes_only_the_managed_operator_command():
    uninstaller = Path("deploy/uninstall.sh").read_text()
    assert 'readlink /usr/local/bin/lattice' in uninstaller
    assert '== "/opt/lattice/venv/bin/lattice"' in uninstaller
    assert 'not the Lattice-managed launcher; leaving it untouched' in uninstaller


def test_bootstrap_is_only_modern_install_plus_guided_setup():
    bootstrap = Path("lattice-bootstrap.sh").read_text()
    assert 'LATTICE_REPO_DIR="$SCRIPT_DIR" "$INSTALLER"' in bootstrap
    assert 'exec /usr/local/bin/lattice init' in bootstrap
    assert "ssh-copy-id" not in bootstrap
    assert "NOPASSWD" not in bootstrap
    assert "authorized_keys" not in bootstrap


def test_legacy_worker_tui_wrapper_is_removed():
    assert not Path("lattice/cli/worker_tui.py").exists()


def test_smoke_test_verifies_operator_command():
    smoke = Path("deploy/smoke-test.sh").read_text()
    assert "/usr/local/bin/lattice --version" in smoke
    assert 'readlink /usr/local/bin/lattice' in smoke


def test_production_installer_never_uses_editable_package_install():
    installer = Path("deploy/install.sh").read_text()
    assert '    -e "$RELEASE_ROOT"' not in installer
    assert "--editable" not in installer
    assert '    "$RELEASE_ROOT" \\' in installer


def test_installer_creates_system_integration_parent_directories():
    installer = Path("deploy/install.sh").read_text()
    assert "install -d -m 0755 /etc/sysusers.d /etc/tmpfiles.d /etc/systemd/system" in installer
    assert "logrotate dbus" not in installer
    assert "rm -f /etc/logrotate.d/lattice" in installer
    assert "install -d -m 0750 /etc/sudoers.d" in installer
    step2 = installer.split('echo "==> [2/7] Ensuring lattice user exists..."', 1)[1].split('# 3. Runtime dirs', 1)[0]
    assert step2.index("/etc/sysusers.d /etc/tmpfiles.d") < step2.index("/etc/sysusers.d/lattice.conf")


def test_installer_removes_only_recognized_legacy_user_launcher():
    installer = Path("deploy/install.sh").read_text()
    assert "cleanup_legacy_user_cli_launcher" in installer
    assert 'legacy="$user_home/.local/bin/lattice"' in installer
    assert "stat -c '%U'" in installer
    assert "from lattice\\.cli\\.main import main" in installer
    assert "sys\\.exit(main())" in installer
    assert 'rm -f -- "$legacy"' in installer


def test_installer_creates_separate_read_only_operator_group():
    installer = Path("deploy/install.sh").read_text()
    sysusers = Path("deploy/sysusers.d/lattice.conf").read_text()
    tmpfiles = Path("deploy/tmpfiles.d/lattice.conf").read_text()
    assert 'OPERATOR_GROUP="lattice-operator"' in installer
    assert 'usermod -a -G "$OPERATOR_GROUP" "$SUDO_USER"' in installer
    assert 'g lattice-operator -' in sysusers
    assert '/run/lattice-operator' in tmpfiles
    assert '2770 lattice lattice-operator' in tmpfiles


def test_installer_repairs_production_config_permissions_and_snapshots_it():
    installer = Path("deploy/install.sh").read_text()
    assert 'chown root:"$LATTICE_GROUP" /etc/lattice/lattice.toml' in installer
    assert 'chmod 0640 /etc/lattice/lattice.toml' in installer
    assert installer.count('/etc/lattice/lattice.toml') >= 4


def test_installer_repairs_master_recovery_key_for_daemon_use():
    installer = Path("deploy/install.sh").read_text()
    assert 'chown "$LATTICE_USER:$LATTICE_GROUP" /etc/lattice/keys/lattice_ed25519' in installer
    assert 'chmod 0600 /etc/lattice/keys/lattice_ed25519' in installer

def test_installer_records_operator_group_created_by_sysusers():
    installer = Path("deploy/install.sh").read_text()

    preexisting = 'OPERATOR_GROUP_PREEXISTED=false'
    sysusers = "systemd-sysusers"
    marker = 'touch "$MANAGED_ACCOUNT_ROOT/managed-group-lattice-operator"'

    assert preexisting in installer
    assert marker in installer
    assert installer.index(preexisting) < installer.index(sysusers)
    assert installer.index(sysusers) < installer.index(marker)



def test_first_install_records_and_restores_host_state_transactionally():
    installer = Path("deploy/install.sh").read_text()
    host_state = Path("deploy/host-state.sh").read_text()
    assert 'source "$SCRIPT_DIR/host-state.sh"' in installer
    assert installer.index("lattice_host_state_snapshot") < installer.index("Installing system packages")
    assert "apt-get install --no-upgrade" in installer
    assert "lattice_host_state_plan_packages" in installer
    assert "lattice_host_state_finalize_packages" in installer
    assert "packages-manualized-by-lattice.txt" in host_state
    assert "packages-planned-by-lattice.txt" in host_state
    assert 'HOST_STATE_CREATED_THIS_INSTALL' in installer
    assert "lattice_host_state_restore" in installer
    assert "apt-get -s remove" in host_state
    assert "package rollback would remove non-Lattice package" in host_state
    assert "packages-before.txt" in host_state


def test_purge_restores_host_state_before_deleting_its_record():
    uninstaller = Path("deploy/uninstall.sh").read_text()
    restore = uninstaller.index("lattice_host_state_restore")
    conditional = uninstaller.index('if [[ "$HOST_STATE_RESTORE_OK" == "true" ]]')
    delete = uninstaller.index("rm -rf /var/lib/lattice-root", conditional)
    assert restore < conditional < delete
    assert "preserved /var/lib/lattice-root so host restoration can be diagnosed or retried" in uninstaller


def test_installer_stages_only_git_tracked_files_and_prunes_releases():
    installer = Path("deploy/install.sh").read_text()
    assert 'git -C "$REPO_DIR" ls-files -z --cached' in installer
    assert "--files-from=-" in installer
    assert "prune_old_releases" in installer
    assert "index <= 3" in installer

def test_upgrade_restarts_only_enabled_or_active_runtime_services():
    installer = Path("deploy/install.sh").read_text()
    assert "restart_installed_runtime_services" in installer
    assert "systemctl is-enabled --quiet" in installer
    assert "systemctl is-active --quiet" in installer
    assert 'systemctl restart "$unit"' in installer
    assert "log out and back in" in installer
