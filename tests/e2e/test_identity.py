"""Read-only permanent identity consistency tests."""
from __future__ import annotations

import pytest

from .conftest import WORKER_HOST, run

pytestmark = pytest.mark.e2e


def _row(command: str) -> list[str]:
    result = run(["sg", "lattice-operator", "-c", f"/opt/lattice/venv/bin/lattice {command}"])
    assert result.returncode == 0, result.stderr
    line = next(line for line in result.stdout.splitlines() if line.startswith(WORKER_HOST))
    return line.split()


def test_e2e_id_001_file_and_shell_use_same_permanent_node_id():
    mount = _row("mounts list")
    shell = _row("shell status")
    assert mount[-1] == shell[-1]
    assert len(mount[-1]) == 36


def test_e2e_id_002_node_id_is_stable_across_repeated_reads():
    first = _row("mounts list")[-1]
    for _ in range(5):
        assert _row("mounts list")[-1] == first
