"""Privileged uninstall Python must not import Lattice from the caller CWD."""

from pathlib import Path
import subprocess
import sys


def test_isolated_python_ignores_cwd_lattice_shadow(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "lattice"
    fake.mkdir()

    (fake / "__init__.py").write_text(
        "SOURCE = 'cwd-shadow'\n"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            (
                "import pathlib, lattice; "
                "print(pathlib.Path(lattice.__file__).resolve())"
            ),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr

    imported = Path(
        result.stdout.strip()
    ).resolve()

    assert not imported.is_relative_to(
        tmp_path.resolve()
    )


def test_uninstall_runs_all_privileged_python_in_isolated_mode() -> None:
    script = Path(
        "deploy/uninstall.sh"
    ).read_text()

    assert (
        '"$CLEANUP_PYTHON" -I -m '
        "lattice.credential_revoke --uninstall"
        in script
    )

    assert (
        '"$CLEANUP_PYTHON" -I -m '
        "lattice.core.ssh_firewall --remove-lattice-rules"
        in script
    )

    assert (
        '"$CLEANUP_PYTHON" -I -m '
        "lattice.ip_change.uninstall_restore"
        in script
    )
