"""Deployment/uninstall safety regressions."""

from pathlib import Path


def _script() -> str:
    return Path(
        "deploy/uninstall.sh"
    ).read_text()


def test_uninstall_can_fall_back_to_versioned_release():
    script = _script()

    assert "find_cleanup_python()" in script
    assert "validate_cleanup_python()" in script

    assert (
        "/opt/lattice/venv/bin/python"
        in script
    )

    assert (
        "find /opt/lattice-releases"
        in script
    )

    assert (
        "-path '*/venv/bin/python'"
        in script
    )

    assert '"$candidate" -I -c' in script
    assert "lattice.__file__" in script
    assert "module.is_relative_to(release)" in script


def test_uninstall_never_silently_skips_security_cleanup():
    script = _script()

    assert (
        "SECURITY_CLEANUP_REQUIRED=false"
        in script
    )

    assert (
        "/var/lib/lattice/pairing.json"
        in script
    )

    assert (
        "/etc/lattice/firewall-rules.json"
        in script
    )

    assert (
        '&& -z "$CLEANUP_PYTHON"'
        in script
    )

    assert (
        "Uninstall stopped before removing program files"
        in script
    )


def test_uninstall_removes_all_installed_release_code():
    script = _script()

    active = script.index(
        "rm -rf /opt/lattice\n"
    )

    releases = script.index(
        "rm -rf /opt/lattice-releases\n"
    )

    purge = script.index(
        'if [[ "$PURGE" == "true" ]]',
        releases,
    )

    assert active < releases < purge


def test_network_restore_uses_validated_cleanup_interpreter():
    script = _script()

    # Do not depend on shell formatting/line wrapping; verify the actual
    # validated interpreter and recovery module are used together.
    restore_section = script[
        script.index(
            'if [[ "$NETWORK_CHOICE" == "r"'
        ):
        script.index(
            'echo "Saved pre-Lattice network settings restored."'
        )
    ]

    assert '"$CLEANUP_PYTHON"' in restore_section
    assert (
        "-m lattice.ip_change.uninstall_restore"
        in restore_section
    )

    assert (
        "Network restore was requested, but no trustworthy "
        "installed Lattice interpreter is available"
        in script
    )

def test_network_mutators_stop_before_saved_network_restore():
    script = _script()
    restore = script.index("-m lattice.ip_change.uninstall_restore")

    for unit in (
        "lattice-network-reconcile.timer",
        "lattice-network-reconcile.service",
        "lattice-network-assignment.path",
        "lattice-network-assignment.service",
        "lattice-boot-recovery.service",
    ):
        stop = script.index(f"systemctl stop {unit}")
        assert stop < restore


def test_uninstall_never_recursively_deletes_systemd_propagation_state():
    script = _script()

    assert "rm -rf /run/systemd/propagate/lattice-*" not in script
    assert "rmdir -- \"$path\"" in script


def test_uninstall_recognizes_permanent_original_network_snapshot():
    script = _script()

    restore_gate = script[
        script.index(
            "if [[ -f /var/lib/lattice-root/ipchange.state"
        ):
        script.index(
            'echo "Lattice previously changed this computer',
        )
    ]

    assert (
        "/var/lib/lattice-root/ipchange.state"
        in restore_gate
    )

    assert (
        "/var/lib/lattice-root/ipchange.original.json"
        in restore_gate
    )


def test_uninstall_supports_explicit_noninteractive_network_choice():
    script = _script()

    assert "--restore-network)" in script
    assert "--keep-network)" in script
    assert 'NETWORK_MODE="restore"' in script
    assert 'NETWORK_MODE="keep"' in script

    restore_choice = script.index(
        'if [[ "$NETWORK_MODE" == "restore" ]]'
    )
    tty_choice = script.index(
        'elif [[ -t 0 ]]',
        restore_choice,
    )

    # Explicit automation choice must win before the TTY fallback.
    assert restore_choice < tty_choice

    assert (
        'NETWORK_CHOICE="R"'
        in script[restore_choice:tty_choice]
    )
