"""Real upgrade and failed-candidate preservation tests."""
from __future__ import annotations

import os
import shlex

import pytest

from .conftest import WORKER_HOST, require_env, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _ok(result, label: str) -> str:
    assert result.returncode == 0, f"{label}\nstdout={result.stdout}\nstderr={result.stderr}"
    return result.stdout.strip()


def test_e2e_upgrade_001_live_upgrade_preserves_worker_health():
    repo = require_env("LATTICE_E2E_WORKER_REPO", "the Worker repository path")
    before = _ok(ssh(WORKER_HOST, "readlink -f /opt/lattice"), "read active release")
    command = f"cd {shlex.quote(repo)} && sudo -n ./deploy/install.sh"
    _ok(ssh(WORKER_HOST, command, timeout=180), "Worker upgrade")
    after = _ok(ssh(WORKER_HOST, "readlink -f /opt/lattice"), "read upgraded release")
    assert after != before
    _ok(ssh(WORKER_HOST, "sudo -n systemctl start lattice-worker.service"), "start Worker")
    assert _ok(ssh(WORKER_HOST, "systemctl is-active lattice-worker.service"), "Worker service") == "active"

def test_e2e_upgrade_002_failed_candidate_preserves_active_release(tmp_path):
    repo = require_env("LATTICE_E2E_WORKER_REPO", "the Worker repository path")
    before = _ok(ssh(WORKER_HOST, "readlink -f /opt/lattice"), "read active release")
    broken = f"/tmp/lattice-e2e-broken-{os.getpid()}"
    setup = (
        f"rm -rf {broken} && cp -a {shlex.quote(repo)} {broken} && "
        f"rm -f {broken}/requirements.lock"
    )
    _ok(ssh(WORKER_HOST, setup, timeout=60), "prepare broken candidate")
    try:
        result = ssh(WORKER_HOST, f"cd {broken} && sudo -n ./deploy/install.sh", timeout=120)
        assert result.returncode != 0, "broken candidate unexpectedly installed"
        after = _ok(ssh(WORKER_HOST, "readlink -f /opt/lattice"), "read preserved release")
        assert after == before
        assert _ok(ssh(WORKER_HOST, "systemctl is-active lattice-worker.service"), "Worker service") == "active"
    finally:
        ssh(WORKER_HOST, f"rm -rf {broken}", timeout=30)
