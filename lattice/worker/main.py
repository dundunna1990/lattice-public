#!/usr/bin/env python3
import sdnotify  # Boot layer: systemd watchdog
"""
Lattice Worker Daemon – starts FastAPI server and heartbeat loop.
"""
import asyncio
import logging
import os
import sys
import json
from pathlib import Path

os.environ.setdefault("LATTICE_CONFIG_PATH", "/etc/lattice/lattice.toml")
os.environ.setdefault("LATTICE_DB_PATH", "/var/lib/lattice/state.sqlite")

import uvicorn
from lattice.core.config import load_config, reconcile_config
from lattice.core.db import get_db_connection
from lattice.core.migrations import run_migrations
from lattice.worker.heartbeat import HeartbeatSender
from lattice.worker.health import HealthChecker
from lattice.daemon.api.worker_app import app as worker_api_app
from lattice.ip_change.monitor import run_monitor_async

logger = logging.getLogger(__name__)
OPERATOR_SOCKET_PATH = os.environ.get("LATTICE_OPERATOR_SOCKET", "/run/lattice-operator/operator.sock")

async def handle_operator_client(reader, writer):
    """Serve one bounded, read-only local Worker status request."""
    from lattice.worker_operator_interface import (
        WorkerOperatorRequestError, execute_worker_operator_request,
    )
    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if not raw or len(raw) > 8192:
            raise WorkerOperatorRequestError("Operator request is empty or too large")
        payload = json.loads(raw.decode("utf-8"))
        response = await asyncio.to_thread(execute_worker_operator_request, payload)
    except (WorkerOperatorRequestError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        response = {"ok": False, "error": str(exc)}
    except asyncio.TimeoutError:
        response = {"ok": False, "error": "Operator request timed out"}
    except Exception:
        logger.exception("Worker operator request failed")
        response = {"ok": False, "error": "Operator request failed"}
    writer.write((json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8"))
    try:
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass

async def run_api_server(started_event: asyncio.Event | None = None):
    config = load_config()
    port = config.wire_format.port
    host = "0.0.0.0"
    logger.info(f"Starting worker API on {host}:{port}")
    from lattice.core.pki import tls_server_options
    config = uvicorn.Config(
        worker_api_app, host=host, port=port, log_level="info", **tls_server_options("worker")
    )
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())
    while not server.started:
        if serve_task.done():
            await serve_task
            raise RuntimeError("Worker HTTPS server stopped before becoming ready")
        await asyncio.sleep(0.05)
    if started_event is not None:
        started_event.set()
    await serve_task

async def main_loop():
    logging.basicConfig(level=logging.INFO)
    notifier = sdnotify.SystemdNotifier()

    async def _watchdog():
        try:
            while True:
                await asyncio.sleep(15)
                notifier.notify("WATCHDOG=1")
        except asyncio.CancelledError:
            pass
    _wd_task = asyncio.create_task(_watchdog())
    logger.info("Starting Lattice Worker Daemon")

    try:
        config = load_config()
        await asyncio.to_thread(reconcile_config, config)
        def _migrate_local_state():
            conn = get_db_connection()
            try:
                run_migrations(conn)
                conn.commit()
            finally:
                conn.close()
        await asyncio.to_thread(_migrate_local_state)
    except Exception as e:
        logger.error(f"Failed to initialize worker state: {e}")
        sys.exit(1)

    # Local health checker
    health = HealthChecker()

    # Heartbeat sender
    heartbeat = HeartbeatSender(config, health)

    heartbeat_task = asyncio.create_task(heartbeat.start())

    try:
        os.unlink(OPERATOR_SOCKET_PATH)
    except FileNotFoundError:
        pass
    operator_server = await asyncio.start_unix_server(
        handle_operator_client, path=OPERATOR_SOCKET_PATH
    )
    os.chmod(OPERATOR_SOCKET_PATH, 0o660)
    logger.info("Listening for local read-only Worker status on %s", OPERATOR_SOCKET_PATH)

    api_started = asyncio.Event()
    api_task = asyncio.create_task(run_api_server(api_started))
    monitor_task = asyncio.create_task(run_monitor_async())
    try:
        await asyncio.wait_for(api_started.wait(), timeout=30)
        notifier.notify("READY=1")
        async with operator_server:
            await asyncio.gather(heartbeat_task, api_task, monitor_task)
    except asyncio.CancelledError:
        logger.info("Shutting down worker daemon...")
    finally:
        heartbeat_task.cancel()
        await asyncio.gather(heartbeat_task, return_exceptions=True)
        await heartbeat.stop()
        api_task.cancel()
        monitor_task.cancel()
        _wd_task.cancel()
        try:
            os.unlink(OPERATOR_SOCKET_PATH)
        except FileNotFoundError:
            pass

def main():
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\nWorker daemon stopped.")

if __name__ == "__main__":
    main()
