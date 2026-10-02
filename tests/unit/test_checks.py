"""
Unit tests for structured health checks.
"""
import pytest
from unittest.mock import patch, MagicMock
from lattice.healing.checks import (
    SystemdChecker, PortChecker, HttpChecker,
    FileChecker, PingChecker, run_check, list_checkers
)

def test_systemd_checker_success():
    checker = SystemdChecker()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = "active"
        mock_run.return_value.returncode = 0
        result = checker.check({"unit": "test.service", "expected": "active"})
        assert result is True

def test_systemd_checker_failure():
    checker = SystemdChecker()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = "inactive"
        mock_run.return_value.returncode = 3
        result = checker.check({"unit": "test.service", "expected": "active"})
        assert result is False

def test_port_checker_success():
    checker = PortChecker()
    with patch("socket.socket") as mock_socket:
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 0
        result = checker.check({"port": 8080})
        assert result is True

def test_port_checker_failure():
    checker = PortChecker()
    with patch("socket.socket") as mock_socket:
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.connect_ex.return_value = 1
        result = checker.check({"port": 8080})
        assert result is False

def test_http_checker_success():
    checker = HttpChecker()
    with patch("httpx.get") as mock_get:
        mock_get.return_value.status_code = 200
        result = checker.check({"url": "http://localhost"})
        assert result is True

def test_http_checker_failure():
    checker = HttpChecker()
    with patch("httpx.get") as mock_get:
        mock_get.return_value.status_code = 500
        result = checker.check({"url": "http://localhost"})
        assert result is False

def test_file_checker_success(tmp_path):
    checker = FileChecker()
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello")
    result = checker.check({"path": str(test_file)})
    assert result is True

def test_file_checker_failure():
    checker = FileChecker()
    result = checker.check({"path": "/non/existent/file"})
    assert result is False

def test_ping_checker_success():
    checker = PingChecker()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        result = checker.check({"host": "127.0.0.1"})
        assert result is True

def test_ping_checker_failure():
    checker = PingChecker()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 1
        result = checker.check({"host": "192.0.2.1"})
        assert result is False

def test_run_check_unknown():
    result = run_check("unknown", {})
    assert result is False

def test_list_checkers():
    checkers = list_checkers()
    assert "systemd" in checkers
    assert "http" in checkers
    assert "ping" in checkers
