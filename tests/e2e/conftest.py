"""Safety gates and helpers for real-machine Lattice E2E tests."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

import pytest

REAL_E2E_ENV = "LATTICE_REAL_E2E"
DESTRUCTIVE_E2E_ENV = "LATTICE_DESTRUCTIVE_E2E"
RESET_E2E_ENV = "LATTICE_FLEET_RESET_E2E"
AUTOHEAL_LIVE_E2E_ENV = "LATTICE_AUTOHEAL_LIVE_E2E"
BACKUP_E2E_ENV = "LATTICE_BACKUP_E2E"
BACKUP_DESTRUCTIVE_E2E_ENV = "LATTICE_BACKUP_DESTRUCTIVE_E2E"
BACKUP_DESTRUCTIVE_CONFIRM_ENV = "LATTICE_BACKUP_DESTRUCTIVE_CONFIRM"
BACKUP_DESTRUCTIVE_CONFIRM_VALUE = "BACKUP-V1-DESTRUCTIVE"
MASTER_HOST = os.environ.get("LATTICE_E2E_MASTER", "").strip()
WORKER_HOST = os.environ.get("LATTICE_E2E_WORKER", "").strip()
BACKUP_HOST = os.environ.get("LATTICE_E2E_BACKUP_HOST", "").strip()
WORKER_USER = os.environ.get("LATTICE_E2E_WORKER_USER", "").strip()
FORBIDDEN_HOSTS = set()


def _short_host(host: str) -> str:
    return host.rstrip(".").split(".", 1)[0].lower()


if BACKUP_HOST:
    FORBIDDEN_HOSTS.add(_short_host(BACKUP_HOST))


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

def _enabled(name: str) -> bool:
    return os.environ.get(name) == "1"


def require_env(name: str, purpose: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.skip(f"set {name} for {purpose}")
    return value


def run(command: list[str], *, timeout: int = 10) -> CommandResult:
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(tuple(command), result.returncode, result.stdout, result.stderr)


def ssh(
    host: str,
    command: str,
    *,
    timeout: int = 10,
    user: str | None = None,
    identity_file: str | None = None,
) -> CommandResult:
    if _short_host(host) in FORBIDDEN_HOSTS:
        raise RuntimeError(f"Refusing E2E access to forbidden host: {host}")

    target = f"{user}@{host}" if user else host

    argv = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=yes",
    ]

    if identity_file is not None:
        argv.extend([
            "-i", identity_file,
            "-o", "IdentitiesOnly=yes",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
        ])

    argv.extend([target, command])
    return run(argv, timeout=timeout)



def backup_ssh(command: str, *, timeout: int = 10) -> CommandResult:
    """SSH only to the explicitly configured and gated Backup host."""
    if not _enabled(BACKUP_E2E_ENV):
        raise RuntimeError(f"Refusing Backup-host SSH without {BACKUP_E2E_ENV}=1")
    if not BACKUP_HOST:
        raise RuntimeError("Set LATTICE_E2E_BACKUP_HOST before running Backup E2E tests.")
    argv = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=yes",
        BACKUP_HOST,
        command,
    ]
    return run(argv, timeout=timeout)

def pytest_collection_modifyitems(config, items):
    real_enabled = _enabled(REAL_E2E_ENV)
    destructive_enabled = _enabled(DESTRUCTIVE_E2E_ENV)
    reset_enabled = _enabled(RESET_E2E_ENV)
    autoheal_live_enabled = _enabled(AUTOHEAL_LIVE_E2E_ENV)
    backup_enabled = _enabled(BACKUP_E2E_ENV)
    backup_destructive_enabled = (
        _enabled(BACKUP_DESTRUCTIVE_E2E_ENV)
        and os.environ.get(BACKUP_DESTRUCTIVE_CONFIRM_ENV) == BACKUP_DESTRUCTIVE_CONFIRM_VALUE
    )

    if real_enabled:
        missing = [
            name for name, value in (
                ("LATTICE_E2E_MASTER", MASTER_HOST),
                ("LATTICE_E2E_WORKER", WORKER_HOST),
            )
            if not value
        ]
        if missing:
            raise pytest.UsageError(
                "Real E2E was enabled without explicit test hosts: " + ", ".join(missing)
            )
    if reset_enabled and not WORKER_USER:
        raise pytest.UsageError("Fleet-reset E2E requires LATTICE_E2E_WORKER_USER.")
    if backup_enabled and not BACKUP_HOST:
        raise pytest.UsageError("Backup E2E requires LATTICE_E2E_BACKUP_HOST.")
    real_skip = pytest.mark.skip(reason=f"set {REAL_E2E_ENV}=1 to run real E2E tests")
    destructive_skip = pytest.mark.skip(reason=f"set {DESTRUCTIVE_E2E_ENV}=1 for destructive E2E tests")
    reset_skip = pytest.mark.skip(reason=f"set {RESET_E2E_ENV}=1 for fleet-reset E2E tests")
    autoheal_live_skip = pytest.mark.skip(reason=f"set {AUTOHEAL_LIVE_E2E_ENV}=1 only after disabling Auto-Heal Dry Run")
    backup_skip = pytest.mark.skip(reason=f"set {BACKUP_E2E_ENV}=1 for real Backup V1 E2E tests")
    backup_destructive_skip = pytest.mark.skip(
        reason=(
            f"set {BACKUP_DESTRUCTIVE_E2E_ENV}=1 and "
            f"{BACKUP_DESTRUCTIVE_CONFIRM_ENV}={BACKUP_DESTRUCTIVE_CONFIRM_VALUE} "
            "only for explicitly authorized Backup destructive E2E"
        )
    )
    for item in items:
        if "e2e" in item.keywords and not real_enabled:
            item.add_marker(real_skip)
        if "destructive_e2e" in item.keywords and not destructive_enabled:
            item.add_marker(destructive_skip)
        if "fleet_reset_e2e" in item.keywords and not reset_enabled:
            item.add_marker(reset_skip)
        if "autoheal_live_e2e" in item.keywords and not autoheal_live_enabled:
            item.add_marker(autoheal_live_skip)
        if "backup_e2e" in item.keywords and not backup_enabled:
            item.add_marker(backup_skip)
        if "backup_destructive_e2e" in item.keywords and not backup_destructive_enabled:
            item.add_marker(backup_destructive_skip)


@pytest.fixture(scope="session")
def e2e_hosts() -> tuple[str, str]:
    if not MASTER_HOST or not WORKER_HOST:
        pytest.skip("set LATTICE_E2E_MASTER and LATTICE_E2E_WORKER for real E2E tests")
    hosts = (MASTER_HOST, WORKER_HOST)
    forbidden = {host for host in hosts if _short_host(host) in FORBIDDEN_HOSTS}
    if forbidden:
        pytest.fail(f"Forbidden E2E host configured: {sorted(forbidden)}")
    if _short_host(MASTER_HOST) == _short_host(WORKER_HOST):
        pytest.fail("Master and Worker E2E hosts must be different")
    return hosts


@pytest.fixture(scope="session")
def evidence_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("lattice-e2e-evidence")
