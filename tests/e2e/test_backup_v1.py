"""Explicitly gated real-fleet Backup V1 smoke and recovery readiness tests."""
from __future__ import annotations

import json
import os
import shlex
import socket
import time

import pytest

from .conftest import (
    BACKUP_HOST,
    MASTER_HOST,
    WORKER_HOST,
    backup_ssh,
    require_env,
    run,
    ssh,
)

pytestmark = [pytest.mark.e2e, pytest.mark.backup_e2e]


def _assert_ok(result, label: str) -> str:
    assert result.returncode == 0, (
        f"{label} failed\ncommand={result.command}\n"
        f"stdout={result.stdout}\nstderr={result.stderr}"
    )
    return result.stdout.strip()




def _operator_request(command: str, params: dict | None = None):
    payload = json.dumps({"command": command, "params": params or {}}, separators=(",", ":"))
    code = (
        "import json,sys; "
        "from lattice.operator_client import request; "
        "p=json.loads(sys.argv[1]); "
        "print(json.dumps(request(p['command'], p['params']), sort_keys=True))"
    )
    result = run([
        "sg", "lattice-operator", "-c",
        f"/opt/lattice/venv/bin/python -c {shlex.quote(code)} {shlex.quote(payload)}",
    ], timeout=15)
    output = _assert_ok(result, f"operator request {command}")
    return json.loads(output)


def _job_state(job_uuid: str) -> dict:
    jobs = _operator_request("backups.jobs")
    matches = [item for item in jobs if item.get("job_uuid") == job_uuid]
    assert len(matches) == 1, f"Expected exactly one backup job {job_uuid}, got {matches!r}"
    return matches[0]


def _wait_for_new_success(job_uuid: str, previous_success: str | None, timeout: int = 900) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = _job_state(job_uuid)
        if job.get("last_result") == "successful" and job.get("last_success_at") != previous_success:
            return job
        time.sleep(5)
    raise AssertionError(f"Backup job {job_uuid} did not produce a new success within {timeout}s")

def _remote_unit_active(host: str, unit: str) -> None:
    result = backup_ssh(f"systemctl is-active {unit}") if host == BACKUP_HOST else ssh(
        host, f"systemctl is-active {unit}"
    )
    assert _assert_ok(result, f"{host} {unit}") == "active"


def _remote_unit_enabled(host: str, unit: str) -> None:
    result = backup_ssh(f"systemctl is-enabled {unit}") if host == BACKUP_HOST else ssh(
        host, f"systemctl is-enabled {unit}"
    )
    assert _assert_ok(result, f"{host} {unit}") == "enabled"


def test_backup_e2e_001_expected_three_node_topology():
    assert socket.gethostname().split('.', 1)[0] == MASTER_HOST.split('.', 1)[0]
    assert WORKER_HOST
    assert BACKUP_HOST
    assert WORKER_HOST.split(".", 1)[0] != BACKUP_HOST.split(".", 1)[0]


def test_backup_e2e_002_pinned_restic_version_on_all_nodes():
    master = run(["/opt/lattice/bin/restic", "version"])
    assert "restic 0.19.1 " in _assert_ok(master, "master Restic version")

    worker = ssh(WORKER_HOST, "/opt/lattice/bin/restic version")
    assert "restic 0.19.1 " in _assert_ok(worker, "worker Restic version")

    target = backup_ssh("/opt/lattice/bin/restic version")
    assert "restic 0.19.1 " in _assert_ok(target, "backup-host Restic version")


def test_backup_e2e_003_source_owned_backup_timers_active_everywhere():
    units = (
        "lattice-backup.timer",
        "lattice-backup-maintenance.timer",
    )
    for unit in units:
        local = run(["systemctl", "is-active", unit])
        assert _assert_ok(local, f"master {unit}") == "active"
        _remote_unit_active(WORKER_HOST, unit)
        _remote_unit_active(BACKUP_HOST, unit)


def test_backup_e2e_004_manual_query_restore_watchers_enabled_everywhere():
    units = (
        "lattice-backup-run-request.path",
        "lattice-backup-query.path",
        "lattice-backup-restore.path",
    )
    for unit in units:
        local = run(["systemctl", "is-enabled", unit])
        assert _assert_ok(local, f"master {unit}") == "enabled"
        _remote_unit_enabled(WORKER_HOST, unit)
        _remote_unit_enabled(BACKUP_HOST, unit)


def test_backup_e2e_005_dedicated_backup_transport_enabled_without_forcing_listener():
    for host in (WORKER_HOST, BACKUP_HOST):
        _remote_unit_enabled(host, "lattice-backup-transport-reconcile.path")
        _remote_unit_enabled(host, "lattice-backup-sshd.service")

    local = run(["systemctl", "is-enabled", "lattice-backup-transport-reconcile.path"])
    assert _assert_ok(local, "master backup transport path") == "enabled"
    local = run(["systemctl", "is-enabled", "lattice-backup-sshd.service"])
    assert _assert_ok(local, "master backup sshd") == "enabled"


def test_backup_e2e_006_backup_host_external_drive_uuid_matches_explicit_test_target():
    filesystem_uuid = require_env(
        "LATTICE_E2E_BACKUP_DEVICE_UUID",
        "read-only Backup V1 external-drive identity verification",
    )
    result = backup_ssh(
        "findmnt --json --source UUID="
        + __import__('shlex').quote(filesystem_uuid)
        + " --output TARGET,UUID,SOURCE,FSTYPE,OPTIONS"
    )
    output = _assert_ok(result, "Backup-host drive identity")
    assert filesystem_uuid in output


def test_backup_e2e_007_no_backup_passwords_visible_to_operator_commands():
    output = json.dumps(_operator_request("backups.jobs"), sort_keys=True).lower()
    assert "password" not in output
    assert "credential" not in output
    assert "/etc/lattice/backup" not in output


@pytest.mark.destructive_e2e
@pytest.mark.backup_destructive_e2e
def test_backup_e2e_write_001_manual_remote_backup_completes():
    job_uuid = require_env(
        "LATTICE_E2E_REMOTE_BACKUP_JOB_UUID",
        "Worker-to-backup-host manual Backup V1 E2E",
    )
    before = _job_state(job_uuid)
    assert before["source_hostname"] == WORKER_HOST
    assert before["target_type"] == "remote_storage"
    command = [
        "sudo", "-n", "/opt/lattice/bin/lattice-backup-control",
        "run-now", job_uuid,
    ]
    started = run(command, timeout=30)
    _assert_ok(started, "manual remote backup request")
    after = _wait_for_new_success(job_uuid, before.get("last_success_at"))
    assert after["state"] in {"healthy", "running"}


@pytest.mark.destructive_e2e
@pytest.mark.backup_destructive_e2e
def test_backup_e2e_write_002_source_backup_survives_master_service_outage():
    job_uuid = require_env(
        "LATTICE_E2E_REMOTE_BACKUP_JOB_UUID",
        "Master-offline source-owned Backup V1 E2E",
    )
    before = _job_state(job_uuid)
    assert before["source_hostname"] == WORKER_HOST
    stop = run(["sudo", "-n", "systemctl", "stop", "lattice-master.service"], timeout=30)
    _assert_ok(stop, "stop master for source-owned backup test")
    try:
        trigger = ssh(
            WORKER_HOST,
            "sudo -n /opt/lattice/bin/lattice-backup-control run-now " + shlex.quote(job_uuid),
            timeout=30,
        )
        _assert_ok(trigger, "worker-local backup request while master is down")

        # Verify success from the source-owned local DB while Master is still down.
        code = (
            "from lattice.core.db import get_db_connection; "
            "c=get_db_connection(); "
            "r=c.execute(\"SELECT br.result,br.finished_at FROM backup_runs br "
            "JOIN backup_jobs bj ON bj.id=br.job_id WHERE bj.job_uuid=? "
            "ORDER BY br.id DESC LIMIT 1\", (" + repr(job_uuid) + ",)).fetchone(); "
            "print('' if r is None else f'{r[0]}|{r[1]}')"
        )
        deadline = time.monotonic() + 900
        latest = ""
        while time.monotonic() < deadline:
            result = ssh(
                WORKER_HOST,
                "/opt/lattice/venv/bin/python -c " + shlex.quote(code),
                timeout=15,
            )
            latest = _assert_ok(result, "worker-local backup run state")
            if latest.startswith("successful|"):
                break
            time.sleep(5)
        assert latest.startswith("successful|"), latest
    finally:
        restart = run(["sudo", "-n", "systemctl", "start", "lattice-master.service"], timeout=30)
        _assert_ok(restart, "restore master after source-owned backup test")


@pytest.mark.backup_destructive_e2e
def test_backup_e2e_destructive_gate_is_separate_from_read_only_suite():
    """Sentinel proving destructive Backup tests require the extra confirmation phrase."""
    assert os.environ.get("LATTICE_BACKUP_DESTRUCTIVE_E2E") == "1"
    assert os.environ.get("LATTICE_BACKUP_DESTRUCTIVE_CONFIRM") == "BACKUP-V1-DESTRUCTIVE"
