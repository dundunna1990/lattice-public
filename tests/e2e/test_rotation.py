"""Live file/shell credential rollover tests."""
from __future__ import annotations

import time

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e]


def _ok(result, label: str) -> str:
    assert result.returncode == 0, f"{label}\nstdout={result.stdout}\nstderr={result.stderr}"
    return result.stdout.strip()


def _fingerprint(path: str) -> str:
    result = ssh(
        WORKER_HOST,
        f"sudo -n ssh-keygen -lf {path}",
        timeout=15,
    )
    return _ok(result, f"fingerprint {path}").split()[1]


def _wait_changed(path: str, before: str, timeout: int = 180) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current = _fingerprint(path)
        if current != before:
            return current
        time.sleep(3)
    pytest.fail(f"credential did not rotate within {timeout}s: {path}")

def test_e2e_file_020_file_key_rotation_converges():
    pub = "/etc/lattice/file-ssh/client_ed25519.pub"
    before = _fingerprint(pub)
    _ok(ssh(WORKER_HOST, "sudo -n touch -d '100 days ago' /etc/lattice/file-ssh/client_ed25519 /etc/lattice/file-ssh/host_ed25519"), "age file keys")
    _ok(ssh(WORKER_HOST, "sudo -n systemctl restart lattice-mount-manager.service"), "restart mount manager")
    after = _wait_changed(pub, before)
    assert after != before
    status = run(["sg", "lattice-operator", "-c", "/opt/lattice/venv/bin/lattice mounts list"])
    assert WORKER_HOST in _ok(status, "mount status")


def test_e2e_shell_020_shell_key_rotation_converges():
    pub = "/etc/lattice/shell-ssh/client_ed25519.pub"
    before = _fingerprint(pub)
    _ok(ssh(WORKER_HOST, "sudo -n touch -d '100 days ago' /etc/lattice/shell-ssh/client_ed25519 /etc/lattice/shell-ssh/host_ed25519"), "age shell keys")
    _ok(ssh(WORKER_HOST, "sudo -n systemctl restart lattice-shell-connection-manager.service"), "restart shell manager")
    after = _wait_changed(pub, before)
    assert after != before
    status = run(["sg", "lattice-operator", "-c", "/opt/lattice/venv/bin/lattice shell status"])
    output = _ok(status, "shell status")
    line = next(line for line in output.splitlines() if line.startswith(WORKER_HOST))
    assert "connected" in line
