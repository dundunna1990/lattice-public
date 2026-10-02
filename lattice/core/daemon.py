"""Daemon control — TUI → daemon communication via Unix socket.

Used by the TUI to ask the running daemon to reload its config.
"""
import logging
import os
import socket as _socket

logger = logging.getLogger(__name__)

DEFAULT_SOCKET_PATH = os.environ.get("LATTICE_SOCKET_PATH", "/run/lattice/master.sock")
DEFAULT_TIMEOUT_SECONDS = 5.0


def reload_daemon(socket_path: str = DEFAULT_SOCKET_PATH,
                  timeout: float = DEFAULT_TIMEOUT_SECONDS) -> bool:
    """Ask the running daemon to reload its config from disk.

    Returns True on success, False on any failure (with a log line).
    Designed to be called from CLI / TUI.
    """
    if not os.path.exists(socket_path):
        logger.error(
            f"Cannot reload: daemon socket not found at {socket_path}. "
            f"Is the daemon running?"
        )
        return False
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect(socket_path)
            except (ConnectionRefusedError, PermissionError) as e:
                logger.error(f"Cannot connect to daemon socket: {e}")
                return False
            try:
                s.sendall(b"RELOAD\n")
                response = b""
                while not response.endswith(b"\n"):
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    response += chunk
            except (_socket.timeout, OSError) as e:
                logger.error(f"Daemon did not respond to RELOAD: {e}")
                return False
        response_str = response.decode(errors="replace").strip()
        if response_str == "RELOAD_OK":
            logger.info("Daemon reloaded config successfully")
            return True
        else:
            logger.error(f"Daemon returned: {response_str}")
            return False
    except OSError as e:
        logger.error(f"reload_daemon failed: {e}")
        return False
