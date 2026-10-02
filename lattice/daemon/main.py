import asyncio
import contextlib
import json
import logging
import os
import signal
import sdnotify  # systemd watchdog/readiness notifications

# systemd captures stdout/stderr into journald. Keep one normal-log owner.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _apply_master_log_level(config) -> None:
    """Apply the configured Master log threshold to the running process."""
    name = str(config.daemon.log_level).upper()
    level = getattr(logging, name, logging.INFO)
    logging.getLogger().setLevel(level)
    logger.setLevel(level)


from fastapi import FastAPI
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from lattice.core.limiter import limiter
import uvicorn

from lattice.core.migrations import run_migrations
from lattice.core.db import get_db_connection
from lattice.core.config import load_config, reconcile_config
from lattice.master.health_check import HealthCheckLoop
from lattice.ip_change.monitor import run_monitor_async
from lattice.api.routes.webhooks import router as webhook_router
from lattice.api.routes.heartbeat import router as heartbeat_router
from lattice.api.routes.dashboard import router as dashboard_router
from lattice.api.routes.workers import router as workers_router
from lattice.api.routes.alerts import router as alerts_router
from lattice.api.routes.events import router as events_router
from lattice.web.app import app as web_app
SOCKET_PATH = os.environ.get("LATTICE_SOCKET_PATH", "/run/lattice/master.sock")  # F353 fix
OPERATOR_SOCKET_PATH = os.environ.get("LATTICE_OPERATOR_SOCKET", "/run/lattice-operator/operator.sock")

master_app = FastAPI(title="Lattice Master API")

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

@master_app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers[name] = value
    return response

# F436/F132: Rate limiting (limiter defined in lattice.core.limiter)
master_app.state.limiter = limiter
master_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
# Middleware enforces default_limits globally (not just routes with @limiter.limit)
try:
    from slowapi.middleware import SlowAPIMiddleware
    master_app.add_middleware(SlowAPIMiddleware)
except ImportError:
    pass  # old slowapi version

# Include API routers
master_app.include_router(webhook_router)
master_app.include_router(heartbeat_router)
master_app.include_router(dashboard_router)
master_app.include_router(workers_router)
master_app.include_router(alerts_router)
master_app.include_router(events_router)

# Include web UI router (mount at root)
master_app.include_router(web_app.router)

import asyncio as _asyncio
import threading as _threading

# Serialize RELOAD commands — only one config reload at a time.
_reload_lock = _threading.Lock()


def _reload_config_sync() -> str:
    """Re-read config and reconcile to DB. Returns a status string for the client.

    Returns "RELOAD_OK" on success, "RELOAD_ERROR: <msg>" on failure.
    This runs in a thread (off the event loop) so it doesn't block the daemon.
    """
    if not _reload_lock.acquire(blocking=False):
        return "RELOAD_ERROR: another reload is in progress"
    try:
        from lattice.core.config import load_config, reconcile_config
        config = load_config()
        reconcile_config(config)
        _apply_master_log_level(config)
        logger.info("Config reloaded and reconciled via socket RELOAD")
        return "RELOAD_OK"
    except Exception as e:
        logger.error(f"Reload failed: {e}")
        return f"RELOAD_ERROR: {e}"
    finally:
        _reload_lock.release()


async def handle_cli_client(reader, writer):
    """Handle a single CLI client connection.

    Supported commands:
    - PING       → PONG
    - RELOAD     → reload config from disk (RELOAD_OK or RELOAD_ERROR: <msg>)
    - anything else → ACK_UNKNOWN: <msg>
    """
    try:
        data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
    except _asyncio.TimeoutError:
        writer.write(b"ACK_ERROR: timeout\n")
        await writer.drain()
        writer.close()
        return
    message = data.decode().strip()
    if message == "PING":
        response = "PONG\n"
    elif message == "RELOAD":
        # Run the blocking reload in a thread; wait up to 10s for it.
        try:
            response = await _asyncio.wait_for(
                _asyncio.to_thread(_reload_config_sync), timeout=10.0
            ) + "\n"
        except _asyncio.TimeoutError:
            response = "RELOAD_ERROR: reload took longer than 10s\n"
    else:
        response = f"ACK_UNKNOWN: {message}\n"
    writer.write(response.encode())
    try:
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass

async def handle_operator_client(reader, writer):
    """Serve one strict read-only operator request as bounded JSON."""
    from lattice.operator_interface import OperatorRequestError, execute_operator_request

    try:
        raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
        if not raw or len(raw) > 8192:
            raise OperatorRequestError("Operator request is empty or too large")
        payload = json.loads(raw.decode("utf-8"))
        response = await asyncio.to_thread(execute_operator_request, payload)
    except (OperatorRequestError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        response = {"ok": False, "error": str(exc)}
    except asyncio.TimeoutError:
        response = {"ok": False, "error": "Operator request timed out"}
    except Exception:
        logger.exception("Read-only operator request failed")
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


class _ManagedUvicornServer(uvicorn.Server):
    """Uvicorn server whose signals are owned by Lattice's main loop."""

    @contextlib.contextmanager
    def capture_signals(self):
        yield


async def run_web_server(started_event: asyncio.Event | None = None):
    # H1 fix: read port from config instead of hardcoding 8080
    from lattice.core.config import load_config as _load_cfg_for_port
    _cfg = _load_cfg_for_port()
    _port = getattr(_cfg.daemon, 'api_port', None) or getattr(_cfg.master, 'api_port', None) or 8080
    from lattice.core.pki import tls_server_options
    config = uvicorn.Config(
        master_app, host="0.0.0.0", port=_port, log_level="info", **tls_server_options("master")
    )
    server = _ManagedUvicornServer(config)
    serve_task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if serve_task.done():
                await serve_task
                raise RuntimeError("Master HTTPS server stopped before becoming ready")
            await asyncio.sleep(0.05)
        if started_event is not None:
            started_event.set()
        await serve_task
    except asyncio.CancelledError:
        # A Lattice shutdown asks Uvicorn to finish its own graceful shutdown
        # instead of abandoning active HTTP connections immediately.
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(serve_task), timeout=10)
        except asyncio.TimeoutError:
            serve_task.cancel()
            await asyncio.gather(serve_task, return_exceptions=True)
        raise

def _bootstrap_master_sync():
    """Initialize DB, audit trust, and config outside the asyncio event loop."""
    conn = get_db_connection()
    try:
        run_migrations(conn)
    finally:
        conn.close()

    # Full audit-chain verification is intentionally done at startup.
    # Normal appends use the trusted-head fast path afterward.
    try:
        from lattice.healing.audit_log import (
            AuditLog,
            DEFAULT_LOG_PATH,
        )

        audit = AuditLog(DEFAULT_LOG_PATH)
        audit.verify_chain()
    except Exception as exc:
        logger.warning(
            "Audit log chain verification failed: %s",
            exc,
        )

    config = load_config()
    reconcile_config(config)
    return config


async def main_loop():
    notifier = sdnotify.SystemdNotifier()
    wd_state = "ENABLED" if os.environ.get("NOTIFY_SOCKET") else "disabled (not running under systemd)"
    print(f"  systemd watchdog: {wd_state}")

    print("Booting Lattice Master Daemon...")

    config = await asyncio.to_thread(_bootstrap_master_sync)
    _apply_master_log_level(config)
    print("Database and Config initialized.")

    shutdown_event = asyncio.Event()
    event_loop = asyncio.get_running_loop()
    registered_signals = []
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            event_loop.add_signal_handler(sig, shutdown_event.set)
            registered_signals.append(sig)
        except (NotImplementedError, RuntimeError):
            pass

    async def _watchdog():
        try:
            while True:
                await asyncio.sleep(15)
                notifier.notify("WATCHDOG=1")
        except asyncio.CancelledError:
            pass

    watchdog_task = asyncio.create_task(_watchdog())
    health_check_loop = HealthCheckLoop(interval_seconds=config.daemon.poll_interval)
    loop_task = asyncio.create_task(health_check_loop.start())
    monitor_task = asyncio.create_task(run_monitor_async())

    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass
    server = await asyncio.start_unix_server(handle_cli_client, path=SOCKET_PATH)
    try:
        import grp
        lattice_gid = grp.getgrnam("lattice").gr_gid
        os.chown(SOCKET_PATH, -1, lattice_gid)
    except KeyError:
        os.chown(SOCKET_PATH, 0, 0)
    os.chmod(SOCKET_PATH, 0o660)
    print(f"Listening for CLI commands on {SOCKET_PATH}")

    try:
        os.unlink(OPERATOR_SOCKET_PATH)
    except FileNotFoundError:
        pass
    operator_server = await asyncio.start_unix_server(
        handle_operator_client, path=OPERATOR_SOCKET_PATH
    )
    os.chmod(OPERATOR_SOCKET_PATH, 0o660)
    print(f"Listening for read-only operator queries on {OPERATOR_SOCKET_PATH}")

    web_started = asyncio.Event()
    web_task = asyncio.create_task(run_web_server(web_started))
    shutdown_task = asyncio.create_task(shutdown_event.wait())

    try:
        await asyncio.wait_for(web_started.wait(), timeout=30)
        notifier.notify("READY=1")

        async with server, operator_server:
            done, _ = await asyncio.wait(
                {loop_task, monitor_task, web_task, shutdown_task},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if shutdown_task in done:
                print("\nShutting down daemon gracefully...")
            else:
                # A background service ending by itself is abnormal. Surface
                # its exception so systemd can restart the daemon.
                for task in done:
                    if task is shutdown_task:
                        continue
                    exc = task.exception()
                    if exc is not None:
                        raise exc
                raise RuntimeError("A Master background task stopped unexpectedly")
    finally:
        notifier.notify("STOPPING=1")
        health_check_loop.stop()

        shutdown_task.cancel()
        monitor_task.cancel()
        loop_task.cancel()
        web_task.cancel()
        watchdog_task.cancel()

        await asyncio.gather(
            shutdown_task,
            monitor_task,
            loop_task,
            web_task,
            watchdog_task,
            return_exceptions=True,
        )

        server.close()
        operator_server.close()
        await asyncio.gather(
            server.wait_closed(),
            operator_server.wait_closed(),
            return_exceptions=True,
        )

        for sig in registered_signals:
            try:
                event_loop.remove_signal_handler(sig)
            except Exception:
                pass

        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        try:
            os.unlink(OPERATOR_SOCKET_PATH)
        except FileNotFoundError:
            pass

def main() -> None:
    """Console-script entry point for the Lattice master daemon."""
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
