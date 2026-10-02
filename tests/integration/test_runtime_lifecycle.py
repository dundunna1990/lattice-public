"""Safe localhost multi-process runtime lifecycle test.

This test uses:
- real master FastAPI/uvicorn process
- real worker FastAPI/uvicorn process
- real HTTPS/TLS sockets
- real worker HeartbeatSender in a child process
- real SQLite state transitions
- real master HealthCheckLoop networking
- harmless fake sudo for restart acceptance

It never modifies the real NIC, firewall, systemd services, or installed
Lattice credentials.
"""

import asyncio
import os
import shutil
import ssl
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations
from lattice.core.pki import (
    ensure_master_identity,
    ensure_worker_csr,
    sign_worker_csr,
)
from lattice.core.http_client import LatticeHTTPClient
from lattice.master.health_check import HealthCheckLoop


pytestmark = [
    pytest.mark.integration,
    pytest.mark.slow,
]


WORKER_NAME = "e2e-worker"
MASTER_NAME = "e2e-master"
TOKEN = "e2e-worker-token-" + ("x" * 48)
API_TOKEN = "e2e-master-api-token-" + ("y" * 32)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def terminate(proc):
    if proc is None:
        return

    if proc.poll() is not None:
        return

    proc.terminate()

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def process_output(proc):
    if proc is None or proc.stdout is None:
        return ""

    if proc.poll() is None:
        return "<process still running>"

    try:
        return proc.stdout.read()
    except Exception:
        return "<could not read process output>"


def wait_https(url, verify, proc, headers=None, timeout=10):
    deadline = time.monotonic() + timeout
    last_error = None

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(
                f"Process exited early ({proc.returncode}):\n"
                f"{process_output(proc)}"
            )

        try:
            response = httpx.get(
                url,
                verify=ssl.create_default_context(
                    cafile=str(verify)
                ),
                headers=headers or {},
                timeout=1.0,
            )

            if response.status_code < 500:
                return response

        except Exception as exc:
            last_error = exc

        time.sleep(0.1)

    raise AssertionError(
        f"HTTPS endpoint did not become ready: {url}\n"
        f"last error={last_error}\n"
        f"process output={process_output(proc)}"
    )


def write_config(path, master_port, worker_port):
    path.write_text(
        f"""
[master]
ip = "127.0.0.1"
api_port = {master_port}
api_token = "{API_TOKEN}"
master_key = "e2e-master-key"

[daemon]
poll_interval = 1
dry_run = false
log_level = "WARNING"

[wire_format]
port = {worker_port}
connect_timeout_seconds = 1
request_timeout_seconds = 2
idle_timeout_seconds = 30
max_connection_lifetime_seconds = 60
max_retry_attempts = 2
retry_initial_backoff_ms = 25
retry_max_backoff_ms = 50
""".strip()
        + "\n"
    )


def start_uvicorn(app, port, cert, key, env):
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        app,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--ssl-certfile",
        str(cert),
        "--ssl-keyfile",
        str(key),
        "--log-level",
        "warning",
    ]

    return subprocess.Popen(
        command,
        cwd=str(Path(__file__).resolve().parents[2]),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def send_real_heartbeat(env, master_port, token_path, status):
    """Run the real HeartbeatSender once in a separate Python process."""

    service_status = (
        "healthy"
        if status == "healthy"
        else "unhealthy"
    )

    script = f"""
import asyncio
from types import SimpleNamespace

import lattice.worker.heartbeat as hb


class Health:
    def check_all(self):
        return [
            {{
                "name": "sshd",
                "status": "{service_status}",
            }}
        ]


async def main():
    config = SimpleNamespace(
        master=SimpleNamespace(
            ip="127.0.0.1",
            api_port={master_port},
        )
    )

    hb.get_worker_master_endpoint = lambda: {{
        "ip": "127.0.0.1",
        "port": {master_port},
        "hostname": None,
    }}

    sender = hb.HeartbeatSender(config, Health())
    sender.hostname = "{WORKER_NAME}"
    sender.token_path = r"{token_path}"

    await sender.send_heartbeat()

    if sender._client is not None:
        await sender._client.aclose()


asyncio.run(main())
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(Path(__file__).resolve().parents[2]),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, (
        f"Heartbeat process failed:\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


@pytest.mark.skipif(
    shutil.which("openssl") is None,
    reason="OpenSSL is required for the real TLS lifecycle test",
)
@pytest.mark.asyncio
async def test_safe_localhost_runtime_lifecycle(
    tmp_path,
    monkeypatch,
):
    master_port = free_port()
    worker_port = free_port()

    db_path = tmp_path / "master.sqlite"
    config_path = tmp_path / "lattice.toml"
    socket_path = tmp_path / "master.sock"
    pki_dir = tmp_path / "pki"
    token_dir = tmp_path / "tokens"
    worker_cert_dir = tmp_path / "worker-certs"
    pairing_path = tmp_path / "pairing.json"
    endpoint_path = tmp_path / "master-endpoint.json"
    monitor_lock = tmp_path / "ip-monitor.lock"
    fake_bin = tmp_path / "bin"
    fake_sudo_log = tmp_path / "fake-sudo.log"

    pki_dir.mkdir()
    token_dir.mkdir()
    worker_cert_dir.mkdir()
    fake_bin.mkdir()

    write_config(
        config_path,
        master_port,
        worker_port,
    )

    worker_token = token_dir / f"{WORKER_NAME}.token"
    worker_token.write_text(TOKEN + "\n")
    worker_token.chmod(0o600)

    fake_sudo = fake_bin / "sudo"
    fake_sudo.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$LATTICE_FAKE_SUDO_LOG"\n'
        "exit 0\n"
    )
    fake_sudo.chmod(0o755)

    monkeypatch.setenv(
        "LATTICE_DB_PATH",
        str(db_path),
    )
    monkeypatch.setenv(
        "LATTICE_CONFIG_PATH",
        str(config_path),
    )
    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki_dir),
    )
    monkeypatch.setenv(
        "LATTICE_TOKEN_DIR",
        str(token_dir),
    )
    monkeypatch.setenv(
        "LATTICE_TOKEN_PATH",
        str(worker_token),
    )
    monkeypatch.setenv(
        "LATTICE_WORKER_CERT_DIR",
        str(worker_cert_dir),
    )

    # Build a completely temporary Lattice CA and server identities.
    master_identity = ensure_master_identity(
        hostname=MASTER_NAME,
        ip="127.0.0.1",
    )

    csr = ensure_worker_csr(
        hostname=WORKER_NAME,
    )

    worker_cert_pem, _ = sign_worker_csr(
        csr,
        hostname=WORKER_NAME,
        ip="127.0.0.1",
    )

    worker_cert = pki_dir / "worker.crt"
    worker_cert.write_text(worker_cert_pem)

    # LatticeHTTPClient uses this file as its TLS trust material.
    # Use the temporary CA while retaining the worker-specific filename.
    pinned_worker_trust = (
        worker_cert_dir
        / f"{WORKER_NAME}.crt"
    )
    pinned_worker_trust.write_bytes(
        master_identity["ca"].read_bytes()
    )

    conn = get_db_connection()
    run_migrations(conn)

    conn.execute(
        """
        INSERT INTO workers (
            hostname,
            status,
            failure_count,
            ssh_user,
            ip,
            ssh_host_key_fingerprint
        )
        VALUES (?, 'unknown', 0, 'e2e', '127.0.0.1', ?)
        """,
        (
            WORKER_NAME,
            "SHA256:e2e-test-only-fingerprint",
        ),
    )

    conn.commit()

    worker_id = conn.execute(
        "SELECT id FROM workers WHERE hostname = ?",
        (WORKER_NAME,),
    ).fetchone()[0]

    conn.close()

    env = os.environ.copy()
    env.update(
        {
            "LATTICE_DB_PATH": str(db_path),
            "LATTICE_CONFIG_PATH": str(config_path),
            "LATTICE_PKI_DIR": str(pki_dir),
            "LATTICE_TOKEN_DIR": str(token_dir),
            "LATTICE_TOKEN_PATH": str(worker_token),
            "LATTICE_WORKER_CERT_DIR": str(
                worker_cert_dir
            ),
            "LATTICE_SOCKET_PATH": str(socket_path),
            "LATTICE_PAIRING_STATE_PATH": str(
                pairing_path
            ),
            "LATTICE_MASTER_ENDPOINT_PATH": str(
                endpoint_path
            ),
            "LATTICE_IP_MONITOR_LOCK": str(
                monitor_lock
            ),
            "LATTICE_API_TOKEN": API_TOKEN,
            "LATTICE_PAIRING_TEST_DIRECT": "1",
            "LATTICE_FAKE_SUDO_LOG": str(
                fake_sudo_log
            ),
            "PATH": (
                str(fake_bin)
                + os.pathsep
                + env.get("PATH", "")
            ),
            "PYTHONPATH": str(
                Path(__file__).resolve().parents[2]
            ),
        }
    )

    master_proc = None
    worker_proc = None

    try:
        # ---------------------------------------------------------
        # Start REAL master HTTPS process.
        # ---------------------------------------------------------
        master_proc = start_uvicorn(
            "lattice.daemon.main:master_app",
            master_port,
            master_identity["cert"],
            master_identity["key"],
            env,
        )

        dashboard_url = (
            f"https://127.0.0.1:{master_port}"
            "/api/dashboard"
        )

        wait_https(
            dashboard_url,
            master_identity["ca"],
            master_proc,
            headers={
                "Authorization":
                f"Bearer {API_TOKEN}"
            },
        )

        # ---------------------------------------------------------
        # Start REAL worker HTTPS process.
        # ---------------------------------------------------------
        worker_proc = start_uvicorn(
            "lattice.daemon.api.worker_app:app",
            worker_port,
            worker_cert,
            pki_dir / "worker.key",
            env,
        )

        health_url = (
            f"https://127.0.0.1:{worker_port}"
            "/v1/health"
        )

        response = wait_https(
            health_url,
            master_identity["ca"],
            worker_proc,
        )

        assert response.status_code == 200
        # This temporary worker has no durable fleet/transport state, so the
        # public endpoint must remain reachable while reporting impairment.
        assert response.json()["status"] == "degraded"

        # ---------------------------------------------------------
        # Real worker HeartbeatSender -> real master HTTPS.
        # ---------------------------------------------------------
        send_real_heartbeat(
            env,
            master_port,
            worker_token,
            "healthy",
        )

        conn = get_db_connection()
        row = conn.execute(
            """
            SELECT status, last_heartbeat_at
            FROM workers
            WHERE id = ?
            """,
            (worker_id,),
        ).fetchone()

        service = conn.execute(
            """
            SELECT status
            FROM services
            WHERE worker_id = ?
              AND name = 'sshd'
            """,
            (worker_id,),
        ).fetchone()

        conn.close()

        assert row["last_heartbeat_at"]
        assert service["status"] == "healthy"

        # ---------------------------------------------------------
        # Master HealthCheckLoop -> REAL worker HTTPS.
        # ---------------------------------------------------------
        runtime_config = SimpleNamespace(
            wire_format=SimpleNamespace(
                port=worker_port,
            )
        )

        import lattice.master.health_check as health_module
        import lattice.core.http_client as http_module

        monkeypatch.setattr(
            health_module,
            "load_config",
            lambda: runtime_config,
        )

        # Deterministic localhost resolution while still exercising
        # LatticeHTTPClient's HTTPS conversion.
        monkeypatch.setattr(
            http_module,
            "tls_hostname",
            lambda _hostname: "127.0.0.1",
        )

        loop = HealthCheckLoop(
            interval_seconds=1
        )

        loop._clients[WORKER_NAME] = (
            LatticeHTTPClient(
                WORKER_NAME,
                token_path=worker_token,
            )
        )

        worker = {
            "id": worker_id,
            "hostname": WORKER_NAME,
            "ip": "127.0.0.1",
            "ssh_user": "e2e",
        }

        await loop._check_worker(worker)

        conn = get_db_connection()
        state = conn.execute(
            """
            SELECT status, failure_count
            FROM workers
            WHERE id = ?
            """,
            (worker_id,),
        ).fetchone()
        conn.close()

        assert state["status"] == "degraded"
        assert state["failure_count"] == 0

        # ---------------------------------------------------------
        # REAL degraded heartbeat must survive successful API poll.
        # ---------------------------------------------------------
        send_real_heartbeat(
            env,
            master_port,
            worker_token,
            "degraded",
        )

        await loop._check_worker(worker)

        conn = get_db_connection()
        state = conn.execute(
            """
            SELECT status, failure_count
            FROM workers
            WHERE id = ?
            """,
            (worker_id,),
        ).fetchone()

        service = conn.execute(
            """
            SELECT status
            FROM services
            WHERE worker_id = ?
              AND name = 'sshd'
            """,
            (worker_id,),
        ).fetchone()

        conn.close()

        assert state["status"] == "degraded"
        assert state["failure_count"] == 0
        assert service["status"] == "unhealthy"

        # Dashboard must expose the real worker.
        dashboard = httpx.get(
            dashboard_url,
            verify=ssl.create_default_context(
                cafile=str(master_identity["ca"])
            ),
            headers={
                "Authorization":
                f"Bearer {API_TOKEN}"
            },
            timeout=3,
        )

        assert dashboard.status_code == 200
        assert WORKER_NAME in dashboard.text

        # ---------------------------------------------------------
        # Real restart endpoint, but PATH redirects sudo to our
        # harmless temporary script.
        # ---------------------------------------------------------
        action = httpx.post(
            (
                f"https://127.0.0.1:"
                f"{worker_port}/v1/actions"
            ),
            verify=ssl.create_default_context(
                cafile=str(master_identity["ca"])
            ),
            headers={
                "Authorization":
                f"Bearer {TOKEN}"
            },
            json={
                "action": "restart",
                "target": "lattice-worker",
            },
            timeout=3,
        )

        assert action.status_code == 202
        assert action.json()["status"] == "accepted"

        deadline = time.monotonic() + 3

        while (
            not fake_sudo_log.exists()
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)

        assert fake_sudo_log.exists()

        sudo_text = fake_sudo_log.read_text()

        assert "lattice-action-exec" in sudo_text
        assert "lattice-worker.service" in sudo_text

        # ---------------------------------------------------------
        # Recheck route through the REAL master process.
        # ---------------------------------------------------------
        recheck = httpx.post(
            (
                f"https://127.0.0.1:"
                f"{master_port}/api/workers/"
                f"{WORKER_NAME}/recheck"
            ),
            verify=ssl.create_default_context(
                cafile=str(master_identity["ca"])
            ),
            headers={
                "Authorization":
                f"Bearer {API_TOKEN}"
            },
            timeout=3,
        )

        assert recheck.status_code == 204

        conn = get_db_connection()
        recheck_value = conn.execute(
            """
            SELECT value
            FROM config
            WHERE key = ?
            """,
            (
                f"health.recheck.{worker_id}",
            ),
        ).fetchone()
        conn.close()

        assert recheck_value is not None
        assert recheck_value[0] == "true"

        # ---------------------------------------------------------
        # Simulate REAL worker process outage.
        #
        # Healing itself is intercepted before SSH/system changes.
        # The health network failure and state machine are real.
        # ---------------------------------------------------------
        terminate(worker_proc)

        repair_probe = AsyncMock()

        monkeypatch.setattr(
            HealthCheckLoop,
            "_evaluate_repair",
            repair_probe,
        )

        for _ in range(3):
            loop._backoff_state.clear()
            await loop._check_worker(worker)

        conn = get_db_connection()
        state = conn.execute(
            """
            SELECT status, failure_count
            FROM workers
            WHERE id = ?
            """,
            (worker_id,),
        ).fetchone()

        failure_events = conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE worker_id = ?
              AND type = 'health_check'
            """,
            (worker_id,),
        ).fetchone()[0]

        conn.close()

        assert state["status"] == "down"
        assert state["failure_count"] >= 3
        assert failure_events >= 3
        assert repair_probe.await_count >= 1

        # ---------------------------------------------------------
        # Restart the temporary worker process.
        # ---------------------------------------------------------
        worker_proc = start_uvicorn(
            "lattice.daemon.api.worker_app:app",
            worker_port,
            worker_cert,
            pki_dir / "worker.key",
            env,
        )

        wait_https(
            health_url,
            master_identity["ca"],
            worker_proc,
        )

        # A heartbeat alone must NOT erase DOWN.
        send_real_heartbeat(
            env,
            master_port,
            worker_token,
            "healthy",
        )

        conn = get_db_connection()
        before_master_recovery = conn.execute(
            """
            SELECT status
            FROM workers
            WHERE id = ?
            """,
            (worker_id,),
        ).fetchone()[0]
        conn.close()

        assert before_master_recovery == "down"

        # Master independently verifies recovery.
        loop._backoff_state.clear()
        await loop._check_worker(worker)

        conn = get_db_connection()
        recovered = conn.execute(
            """
            SELECT status, failure_count
            FROM workers
            WHERE id = ?
            """,
            (worker_id,),
        ).fetchone()

        final_service = conn.execute(
            """
            SELECT status
            FROM services
            WHERE worker_id = ?
              AND name = 'sshd'
            """,
            (worker_id,),
        ).fetchone()

        conn.close()

        assert recovered["status"] == "degraded"
        assert recovered["failure_count"] == 0
        assert final_service["status"] == "healthy"

        await loop._clients[WORKER_NAME].aclose()

    finally:
        terminate(worker_proc)
        terminate(master_proc)
