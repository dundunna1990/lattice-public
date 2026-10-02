from pathlib import Path


MASTER = Path("deploy/systemd/lattice-master.service")
WORKER = Path("deploy/systemd/lattice-worker.service")


def test_master_role_guard_does_not_stop_worker_preemptively():
    unit = MASTER.read_text()

    assert "ExecCondition=/usr/bin/grep -qx master /etc/lattice/role" in unit
    assert "Conflicts=lattice-worker.service" not in unit


def test_worker_role_guard_does_not_stop_master_preemptively():
    unit = WORKER.read_text()

    assert "ExecCondition=/usr/bin/grep -qx worker /etc/lattice/role" in unit
    assert "Conflicts=lattice-master.service" not in unit


def test_role_units_keep_separate_entrypoints():
    master = MASTER.read_text()
    worker = WORKER.read_text()

    assert "ExecStart=/opt/lattice/venv/bin/python -m lattice.daemon.main" in master
    assert "ExecStart=/opt/lattice/venv/bin/python -m lattice.worker.main" in worker
