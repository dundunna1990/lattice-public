from pathlib import Path


def test_backup_control_helper_sets_canonical_runtime_paths():
    helper = Path('deploy/lattice-backup-control').read_text()
    assert 'export LATTICE_CONFIG_PATH=/etc/lattice/lattice.toml' in helper
    assert 'export LATTICE_DB_PATH=/var/lib/lattice/state.sqlite' in helper
    assert 'export LATTICE_SOCKET_PATH=/run/lattice/master.sock' in helper
    assert 'cd /opt/lattice' in helper
    assert 'exec /opt/lattice/venv/bin/python -I -m lattice.backup.control "$@"' in helper


def test_backup_control_helper_does_not_source_caller_or_shell_environment():
    helper = Path('deploy/lattice-backup-control').read_text()
    assert 'source ' not in helper
    assert '. /etc/lattice/environment' not in helper
    assert 'env_keep' not in helper
