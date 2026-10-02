"""
Structured health checks (registered checkers only).
Replaces arbitrary shell commands with typed checks.
"""
import logging
import subprocess
import socket
import os
from typing import Dict, Any, Callable, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class HealthChecker(ABC):
    """Base class for all health checkers."""
    @abstractmethod
    def check(self, params: Dict[str, Any]) -> bool:
        """Run the check and return True if healthy."""
        pass

    @abstractmethod
    def name(self) -> str:
        """Return the checker name."""
        pass

class SystemdChecker(HealthChecker):
    """Check a systemd unit status."""
    def name(self) -> str:
        return "systemd"

    def check(self, params: Dict[str, Any]) -> bool:
        unit = params.get("unit")
        expected = params.get("expected", "active")
        if not unit:
            logger.error("Systemd checker missing 'unit' param")
            return False
        try:
            result = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() == expected
        except Exception as e:
            logger.error(f"Systemd check failed for {unit}: {e}")
            return False

class PortChecker(HealthChecker):
    """Check if a TCP port is listening."""
    def name(self) -> str:
        return "port"

    def check(self, params: Dict[str, Any]) -> bool:
        port = params.get("port")
        host = params.get("host", "127.0.0.1")
        timeout = params.get("timeout", 2)
        if not port:
            logger.error("Port checker missing 'port' param")
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port)) == 0
            sock.close()
            return result
        except Exception as e:
            logger.error(f"Port check failed for {host}:{port}: {e}")
            return False

class HttpChecker(HealthChecker):
    """Check an HTTP endpoint."""
    def name(self) -> str:
        return "http"

    def check(self, params: Dict[str, Any]) -> bool:
        import httpx
        url = params.get("url")
        expected_status = params.get("expected_status", 200)
        timeout = params.get("timeout", 5)
        if not url:
            logger.error("HTTP checker missing 'url' param")
            return False
        try:
            response = httpx.get(url, timeout=timeout)
            return response.status_code == expected_status
        except Exception as e:
            logger.error(f"HTTP check failed for {url}: {e}")
            return False

class FileChecker(HealthChecker):
    """Check if a file exists."""
    def name(self) -> str:
        return "file"

    def check(self, params: Dict[str, Any]) -> bool:
        path = params.get("path")
        if not path:
            logger.error("File checker missing 'path' param")
            return False
        try:
            return os.path.exists(path)
        except Exception as e:
            logger.error(f"File check failed for {path}: {e}")
            return False

class PingChecker(HealthChecker):
    """Check if a host is reachable via ping."""
    def name(self) -> str:
        return "ping"

    def check(self, params: Dict[str, Any]) -> bool:
        host = params.get("host")
        if not host:
            logger.error("Ping checker missing 'host' param")
            return False
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", host],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Ping check failed for {host}: {e}")
            return False

# Registry of available checkers
_CHECKER_REGISTRY: Dict[str, HealthChecker] = {
    "systemd": SystemdChecker(),
    "port": PortChecker(),
    "http": HttpChecker(),
    "file": FileChecker(),
    "ping": PingChecker(),
}

def get_checker(name: str) -> Optional[HealthChecker]:
    """Get a checker by name."""
    return _CHECKER_REGISTRY.get(name)

def run_check(checker_name: str, params: Dict[str, Any]) -> bool:
    """
    Run a structured health check.
    Returns True if healthy.
    """
    checker = get_checker(checker_name)
    if not checker:
        logger.error(f"Unknown checker: {checker_name}")
        return False
    return checker.check(params)

def list_checkers() -> Dict[str, str]:
    """Return a dict of checker names and descriptions."""
    return {
        "systemd": "Check systemd unit status",
        "port": "Check if a TCP port is listening",
        "http": "Check HTTP endpoint status code",
        "file": "Check if a file exists",
        "ping": "Check if a host is reachable",
    }
