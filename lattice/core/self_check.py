"""lattice.core.self_check — periodic health check (lattice-health-check.service)."""
import logging
from pathlib import Path
import socket
import sys

logger = logging.getLogger(__name__)

AUDIT_WARN_BYTES = 75 * 1024 * 1024
AUDIT_CRITICAL_BYTES = 90 * 1024 * 1024
DEFAULT_AUDIT_LOG_PATH = Path("/var/log/lattice/heal_audit.log")


def audit_log_capacity(path: Path = DEFAULT_AUDIT_LOG_PATH) -> tuple[int, str | None]:
    """Return audit-log size and alert severity without modifying the file."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return 0, None

    if size >= AUDIT_CRITICAL_BYTES:
        return size, "error"
    if size >= AUDIT_WARN_BYTES:
        return size, "warn"
    return size, None


def check_db():
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("SELECT 1")
        c.fetchone()
    finally:
        conn.close()


def check_socket(path="/run/lattice/master.sock", timeout=2):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(b"PING\n")
        if s.recv(64).strip() != b"PONG":
            raise RuntimeError("unexpected response")
    finally:
        s.close()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [self_check] %(levelname)s %(message)s")
    from lattice.core.events import (
        resolve_legacy_master_self_check_alerts,
        sync_master_self_check_alert,
    )

    failed = False
    for name, fn in [("db", check_db), ("socket", check_socket)]:
        try:
            fn()
            logger.info("  %s: OK", name)
            sync_master_self_check_alert(name, None)
        except Exception as exc:
            logger.error("  %s: FAIL (%s)", name, exc)
            try:
                sync_master_self_check_alert(name, str(exc))
            except Exception as alert_error:
                logger.error("Could not synchronize master self-check alert: %s", alert_error)
            failed = True

    size, audit_severity = audit_log_capacity()
    if audit_severity is None:
        logger.info("  audit_log: OK (%0.1f MB)", size / (1024 * 1024))
        sync_master_self_check_alert("audit_log", None)
    else:
        message = (
            f"tamper-evident audit log is {size / (1024 * 1024):.1f} MB; "
            "Lattice never generic-rotates this security record"
        )
        log = logger.error if audit_severity == "error" else logger.warning
        log("  audit_log: %s", message)
        try:
            sync_master_self_check_alert(
                "audit_log", message, severity=audit_severity
            )
        except Exception as alert_error:
            logger.error("Could not synchronize audit-capacity alert: %s", alert_error)

    if failed:
        sys.exit(1)

    # Only after every component passes in this same run is it safe to retire
    # historical generic self-check alerts created by older Lattice releases.
    resolved = resolve_legacy_master_self_check_alerts()
    if resolved:
        logger.info("Resolved %s historical Master self-check alert(s)", resolved)
    logger.info("self_check: all green.")


if __name__ == "__main__":
    main()
