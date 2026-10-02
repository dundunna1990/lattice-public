"""Regression tests for the final full-project audit repairs."""

import json
import socket
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lattice.master.health_check import HealthCheckLoop
from lattice.onboarding import PairingError
from lattice.pairing import _wait_for_worker_at_address


async def test_real_api_outage_uses_ssh_as_second_signal_before_healing():
    engine = MagicMock()
    engine.attempt_heal = AsyncMock(return_value=False)

    writer = MagicMock()
    writer.wait_closed = AsyncMock()

    probe = AsyncMock(
        return_value=(MagicMock(), writer)
    )

    with patch(
        "lattice.master.health_check.AutoHealEngine",
        return_value=engine,
    ), patch(
        "lattice.master.health_check.asyncio.open_connection",
        probe,
    ), patch(
        "lattice.master.health_check.log_event",
        return_value=123,
    ) as event:
        await HealthCheckLoop._evaluate_repair(
            7,
            "10.77.0.201",
        )

    probe.assert_awaited_once_with(
        "10.77.0.201",
        22,
    )
    event.assert_called_once()
    assert (
        event.call_args.args[1]
        == "ssh_probe.worker_api_down"
    )
    engine.attempt_heal.assert_awaited_once()
    engine.report_protected_issue.assert_not_called()


async def test_unreachable_ssh_alerts_and_never_attempts_a_restart():
    engine = MagicMock()
    engine.attempt_heal = AsyncMock(return_value=False)

    with patch(
        "lattice.master.health_check.AutoHealEngine",
        return_value=engine,
    ), patch(
        "lattice.master.health_check.asyncio.open_connection",
        new=AsyncMock(side_effect=OSError("down")),
    ):
        await HealthCheckLoop._evaluate_repair(
            7,
            "10.77.0.201",
        )

    engine.attempt_heal.assert_not_awaited()
    engine.report_protected_issue.assert_called_once()


class _SecureSocket:
    def __init__(self, response: bytes):
        self.response = response
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def sendall(self, value):
        self.sent += value

    def recv(self, _size):
        value, self.response = self.response, b""
        return value


def test_static_ip_success_requires_the_exact_address_and_root_result(tmp_path):
    body = json.dumps({"status": "complete", "address": "10.77.0.201"}).encode()
    secure = _SecureSocket(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    context = MagicMock()
    context.wrap_socket.return_value = secure
    certificate = tmp_path / "worker.crt"
    certificate.write_text("test")
    raw = MagicMock()
    raw.__enter__.return_value = raw

    with patch("lattice.pairing.ssl.create_default_context", return_value=context), \
         patch("lattice.pairing.socket.create_connection", return_value=raw) as connect:
        _wait_for_worker_at_address(
            "10.77.0.201", "worker-one", 9999, "token", 1, 0, lambda _: None, certificate
        )

    connect.assert_called_once_with(("10.77.0.201", 9999), timeout=10)
    assert b"GET /v1/network/assignment-status" in secure.sent
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "worker-one.local"


def test_static_ip_proof_rejects_a_different_address(tmp_path):
    body = json.dumps({"status": "complete", "address": "10.77.0.202"}).encode()
    secure = _SecureSocket(b"HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n" + body)
    context = MagicMock()
    context.wrap_socket.return_value = secure
    certificate = tmp_path / "worker.crt"
    certificate.write_text("test")
    raw = MagicMock()
    raw.__enter__.return_value = raw

    with patch("lattice.pairing.ssl.create_default_context", return_value=context), \
         patch("lattice.pairing.socket.create_connection", return_value=raw):
        with pytest.raises(PairingError, match="did not come back"):
            _wait_for_worker_at_address(
                "10.77.0.201", "worker-one", 9999, "token", 1, 0, lambda _: None, certificate
            )
