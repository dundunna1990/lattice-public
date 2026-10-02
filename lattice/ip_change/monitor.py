"""Observe the configured address and alert on drift without changing it."""

import asyncio
import fcntl
import logging
import os
from pathlib import Path
import subprocess
import time

from lattice.ip_change.state import read_expected_network


logger = logging.getLogger(__name__)


def _run(command, **kwargs):
    return subprocess.run(command, **kwargs)


def get_actual_ip(interface, runner=_run):
    result = runner(
        ["ip", "-4", "-o", "address", "show", "dev", interface],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Could not read the interface address").strip())
    for token in result.stdout.split():
        if "/" in token and token[0].isdigit():
            return token.split("/", 1)[0]
    return None


def check_ip_drift_once(runner=_run):
    expected = read_expected_network()
    if not expected:
        return {"status": "not_configured"}

    interface = expected["interface"]
    expected_ip = expected["address"]
    actual_ip = get_actual_ip(interface, runner)
    status = "ok" if actual_ip == expected_ip else "drift"
    result = {
        "status": status,
        "interface": interface,
        "expected": expected_ip,
        "actual": actual_ip,
    }
    if status == "drift":
        logger.error(
            "Static-IP drift detected on %s: expected %s, found %s; no automatic change was made",
            interface,
            expected_ip,
            actual_ip or "no IPv4 address",
        )
    return result



def _sync_master_reconcile_alert():
    try:
        role = Path("/etc/lattice/role").read_text(encoding="utf-8").strip()
    except OSError:
        return
    if role != "master":
        return
    from lattice.ip_change.reconcile import read_network_health
    health = read_network_health()
    if health is None:
        return
    from lattice.core.events import sync_network_reconcile_alert
    import socket
    sync_network_reconcile_alert(None, socket.gethostname(), str(health.get("state") or ""))

def run_monitor(interval=60):
    lock_path = Path(os.environ.get("LATTICE_IP_MONITOR_LOCK", "/run/lattice/ip_monitor.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = lock_path.open("w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.info("IP monitor already running; exiting")
        lock_fd.close()
        return

    logger.info("Read-only IP monitor started")
    try:
        while True:
            try:
                check_ip_drift_once()
            except Exception:
                logger.exception("IP monitor check failed; no network change was made")
            finally:
                time.sleep(interval)
    finally:
        lock_fd.close()


async def run_monitor_async(interval=60):
    """Cancellable monitor used by both the master and worker daemons."""
    lock_path = Path(os.environ.get("LATTICE_IP_MONITOR_LOCK", "/run/lattice/ip_monitor.lock"))
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = lock_path.open("w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.info("IP monitor already running; exiting")
        lock_fd.close()
        return

    logger.info("Read-only IP monitor started")
    try:
        while True:
            try:
                await asyncio.to_thread(check_ip_drift_once)
                await asyncio.to_thread(_sync_master_reconcile_alert)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("IP monitor check failed; no network change was made")
            await asyncio.sleep(interval)
    finally:
        lock_fd.close()


if __name__ == "__main__":
    run_monitor()
