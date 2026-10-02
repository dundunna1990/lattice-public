"""Full revoke / bad-code / local-approval / re-pair cycle."""
from __future__ import annotations

import dataclasses
import json
import shlex
import subprocess
import time

import pytest

from .conftest import WORKER_HOST, WORKER_USER, run, ssh

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.destructive_e2e,
    pytest.mark.fleet_reset_e2e,
]


def _ok(result, label: str) -> str:
    assert result.returncode == 0, f"{label}\nstdout={result.stdout}\nstderr={result.stderr}"
    return result.stdout.strip()


def _worker_ip() -> str:
    result = run(["getent", "hosts", f"{WORKER_HOST}.local"])
    return _ok(result, "resolve Worker").split()[0]


def _prepare_offer(ip: str) -> dict:
    code = (
        "import dataclasses,json; from lattice.onboarding import prepare_worker_pairing; "
        f"o=prepare_worker_pairing({WORKER_HOST!r},{WORKER_USER!r}); print(json.dumps(dataclasses.asdict(o)))"
    )
    result = ssh(
        ip,
        "sudo -n /opt/lattice/venv/bin/python -c " + shlex.quote(code),
        timeout=30,
        user=WORKER_USER,
    )
    return json.loads(_ok(result, "prepare Worker pairing").splitlines()[-1])


def _pair_process(ip: str, offer: dict, code_value: str):
    code = (
        "from lattice.pairing import pair_worker; "
        f"print(pair_worker(hostname={WORKER_HOST!r}, worker_ip={ip!r}, "
        f"pairing_id={offer['pairing_id']!r}, code={code_value!r}))"
    )
    return subprocess.Popen(
        [
            "sudo", "-n", "env",
            "LATTICE_DB_PATH=/var/lib/lattice/state.sqlite",
            "/opt/lattice/venv/bin/python",
            "-c",
            code,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _wait_for_approval_request(
    pairing: subprocess.Popen,
    ip: str,
    timeout: int = 30,
) -> None:
    """Wait until the Worker has received the Master's approval request."""
    deadline = time.monotonic() + timeout
    last_status = ""

    while time.monotonic() < deadline:
        if pairing.poll() is not None:
            out, err = pairing.communicate()
            pytest.fail(
                "Master pairing process exited before Worker approval "
                f"was requested.\nstdout={out}\nstderr={err}"
            )

        status = ssh(
            ip,
            "sudo -n /opt/lattice/venv/bin/lattice pairing status",
            timeout=15,
            user=WORKER_USER,
        )

        last_status = (
            (status.stdout or "")
            + "\n"
            + (status.stderr or "")
        ).strip()

        if (
            status.returncode == 0
            and "Pairing status: awaiting_approval"
            in status.stdout
        ):
            return

        time.sleep(0.5)

    # Do not leave a Master-side pairing subprocess behind when the
    # synchronization point never arrives.
    pairing.terminate()

    try:
        out, err = pairing.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        pairing.kill()
        out, err = pairing.communicate(timeout=5)

    pytest.fail(
        "Worker never reached awaiting_approval. "
        f"Last Worker status:\n{last_status}\n"
        f"Master stdout={out}\nMaster stderr={err}"
    )


def _wait_healthy(timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = run(["sg", "lattice-operator", "-c", f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"])
        if status.returncode == 0 and "Status: healthy" in status.stdout:
            return
        time.sleep(2)
    pytest.fail("Worker did not return healthy after re-pair")


def _wait_mount_and_shell(timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    last_mounts = ""
    last_shell = ""

    while time.monotonic() < deadline:
        mounts = run([
            "sg",
            "lattice-operator",
            "-c",
            "/opt/lattice/venv/bin/lattice mounts list",
        ])
        shell = run([
            "sg",
            "lattice-operator",
            "-c",
            "/opt/lattice/venv/bin/lattice shell status",
        ])

        last_mounts = mounts.stdout + mounts.stderr
        last_shell = shell.stdout + shell.stderr

        mount_ready = (
            mounts.returncode == 0
            and any(
                line.startswith(WORKER_HOST)
                and "mounted" in line
                for line in mounts.stdout.splitlines()
            )
        )

        shell_ready = (
            shell.returncode == 0
            and any(
                line.startswith(WORKER_HOST)
                and "connected" in line
                for line in shell.stdout.splitlines()
            )
        )

        if mount_ready and shell_ready:
            return

        time.sleep(2)

    pytest.fail(
        "Worker became healthy, but mount/shell did not converge.\n"
        f"mounts:\n{last_mounts}\n"
        f"shell:\n{last_shell}"
    )

def test_e2e_remove_pair_cycle_rejects_bad_code_then_recovers():
    """Covers E2E-REMOVE-001/002 and E2E-PAIR-001/002 as one recoverable transaction."""
    ip = _worker_ip()
    removed = subprocess.run(
        [
            "sudo", "-n", "env",
            "LATTICE_DB_PATH=/var/lib/lattice/state.sqlite",
            "/opt/lattice/venv/bin/lattice",
            "workers", "remove", WORKER_HOST,
        ],
        input="y\n", text=True, capture_output=True, timeout=90, check=False,
    )
    assert removed.returncode == 0, removed.stderr or removed.stdout

    offer = _prepare_offer(ip)
    bad = _pair_process(ip, offer, "000000")
    bad_out, bad_err = bad.communicate(timeout=45)
    assert bad.returncode != 0, bad_out
    assert "pair" in (bad_err + bad_out).lower()

    offer = _prepare_offer(ip)
    pairing = _pair_process(ip, offer, offer["code"])
    _wait_for_approval_request(pairing, ip)
    approved = ssh(
        ip,
        "sudo -n /opt/lattice/venv/bin/lattice pairing approve",
        timeout=30,
        user=WORKER_USER,
    )
    _ok(approved, "local pairing approval")
    out, err = pairing.communicate(timeout=120)
    assert pairing.returncode == 0, f"re-pair failed\nstdout={out}\nstderr={err}"

    _wait_healthy()
    _wait_mount_and_shell()
