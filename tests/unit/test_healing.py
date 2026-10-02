"""Tests for the owner-approved, alert-first self-healing policy."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from types import SimpleNamespace
import httpx

from lattice.core.db import get_db_connection
from lattice.healing.engine import AutoHealEngine
from lattice.healing.policy import (
    MODE_ALERT_ONLY,
    record_restart_attempt,
    restart_budget_available,
)


async def test_alert_only_mode_creates_an_alert_without_contacting_or_restarting_worker():
    engine = AutoHealEngine()

    with patch("lattice.healing.engine.get_config_value", return_value=MODE_ALERT_ONLY):
        with patch("lattice.healing.engine.log_event", return_value=42) as event:
            with patch("lattice.healing.engine.create_alert") as alert:
                with patch.object(engine.audit, "log_entry") as audit:
                    with patch("lattice.healing.engine.LatticeHTTPClient") as client:
                        result = await engine.attempt_heal(
                            1,
                            "lattice-worker",
                            "restart",
                            {"reason": "health endpoint did not answer"},
                        )

    assert result is False
    event.assert_called_once()
    alert.assert_called_once()
    audit.assert_called_once()
    assert audit.call_args.kwargs["result"] == "alert_only"
    client.assert_not_called()


def test_protected_ssh_issue_alerts_without_trying_to_change_ssh():
    engine = AutoHealEngine()

    with patch("lattice.healing.engine.log_event", return_value=43) as event:
        with patch("lattice.healing.engine.create_alert") as alert:
            with patch.object(engine.audit, "log_entry") as audit:
                assert engine.report_protected_issue(1, "SSH", "port 22 is unreachable") is False

    event.assert_called_once()
    alert.assert_called_once()
    assert audit.call_args.kwargs["action"] == "none"


def test_restart_budget_stops_after_two_attempts_in_fifteen_minutes():
    conn = get_db_connection()
    conn.execute("DELETE FROM healing_attempts WHERE worker_id = 1 AND service = 'lattice-worker'")
    conn.commit()
    conn.close()
    now = datetime.now(timezone.utc)

    assert restart_budget_available(1, "lattice-worker", now) is True
    record_restart_attempt(1, "lattice-worker", now=now)
    assert restart_budget_available(1, "lattice-worker", now + timedelta(seconds=1)) is True
    record_restart_attempt(1, "lattice-worker", now=now + timedelta(seconds=1))
    assert restart_budget_available(1, "lattice-worker", now + timedelta(seconds=2)) is False


async def test_accepted_restart_must_pass_a_follow_up_health_check():
    engine = AutoHealEngine()
    accepted = SimpleNamespace(status_code=202)
    health_responses = iter(
        [
            SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "status": "healthy",
                    "instance_id": "before",
                },
            ),
            SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "status": "healthy",
                    "instance_id": "after",
                },
            ),
        ]
    )

    async def post(*_args, **_kwargs):
        return accepted

    async def get(*_args, **_kwargs):
        return next(health_responses)

    async def aclose():
        return None

    client = SimpleNamespace(
        post=post,
        get=get,
        aclose=aclose,
    )
    config = SimpleNamespace(daemon=SimpleNamespace(dry_run=False), wire_format=SimpleNamespace(port=9999))

    with patch.object(engine, "should_heal", return_value=True), \
         patch("lattice.healing.engine.get_config_value", return_value="automatic"), \
         patch("lattice.healing.engine.reserve_restart_attempt", return_value=True), \
         patch("lattice.healing.engine.LatticeHTTPClient", return_value=client), \
         patch("lattice.healing.engine.load_config", return_value=config), \
         patch("lattice.healing.engine.asyncio.sleep"), \
         patch.object(engine.audit, "log_entry"), \
         patch("lattice.healing.engine.log_event"):
        assert await engine.attempt_heal(1, "lattice-worker", "restart") is True


async def test_transport_failure_uses_exact_forced_ssh_restart_then_verifies(tmp_path):
    private_key = tmp_path / "lattice_ed25519"
    known_hosts = tmp_path / "known_hosts"
    private_key.write_text("private")
    known_hosts.write_text("known host")
    commands = []

    def ssh_runner(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    class OfflineThenHealthy:
        def __init__(self):
            self.health_calls = 0

        async def post(self, *_args, **_kwargs):
            raise httpx.ConnectError(
                "worker API offline"
            )

        async def get(self, *_args, **_kwargs):
            self.health_calls += 1
            instance_id = (
                "before"
                if self.health_calls == 1
                else "after"
            )
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "status": "healthy",
                    "instance_id": instance_id,
                },
            )

        async def aclose(self):
            return None

    engine = AutoHealEngine(ssh_runner=ssh_runner)
    config = SimpleNamespace(
        master=SimpleNamespace(ip="127.0.0.1"),
        wire_format=SimpleNamespace(port=9999),
    )
    with patch("lattice.healing.engine.SSH_PRIVATE_KEY", private_key), \
         patch("lattice.healing.engine.SSH_KNOWN_HOSTS", known_hosts), \
         patch("lattice.healing.engine.LatticeHTTPClient", return_value=OfflineThenHealthy()), \
         patch("lattice.healing.engine.load_config", return_value=config), \
         patch("lattice.healing.engine.asyncio.sleep"), \
         patch("lattice.healing.engine.log_event"), \
         patch.object(engine.audit, "log_entry", return_value=True):
        assert await engine._attempt_heal_locked(1, "lattice-worker", "restart", {}) is True

    assert commands == [[
        "ssh", "-i", str(private_key),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "HostKeyAlias=test-worker",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "BindAddress=127.0.0.1",
        "--", "testuser@127.0.0.1", "restart lattice-worker.service",
    ]]


async def test_unsavable_audit_stops_before_worker_or_ssh_action():
    ssh_runner = __import__("unittest.mock", fromlist=["MagicMock"]).MagicMock()
    engine = AutoHealEngine(ssh_runner=ssh_runner)
    with patch.object(engine.audit, "log_entry", return_value=False), \
         patch("lattice.healing.engine.LatticeHTTPClient") as client, \
         patch("lattice.healing.engine.log_event", return_value=1), \
         patch("lattice.healing.engine.create_alert"):
        assert await engine._attempt_heal_locked(1, "lattice-worker", "restart", {}) is False
    client.assert_not_called()
    ssh_runner.assert_not_called()


async def test_restart_is_not_success_when_instance_id_does_not_change():
    engine = AutoHealEngine()

    class NeverRestarted:
        async def get(self, *_args, **_kwargs):
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "status": "healthy",
                    "instance_id": "same-process",
                },
            )

    with patch(
        "lattice.healing.engine.asyncio.sleep"
    ):
        assert (
            await engine._verify_worker_recovery(
                NeverRestarted(),
                "127.0.0.1",
                9999,
                "same-process",
            )
            is False
        )


async def test_restart_succeeds_only_after_instance_changes():
    engine = AutoHealEngine()
    values = iter(
        [
            "same-process",
            "new-process",
        ]
    )

    class Restarted:
        async def get(self, *_args, **_kwargs):
            instance = next(values)
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "status": "healthy",
                    "instance_id": instance,
                },
            )

    with patch(
        "lattice.healing.engine.asyncio.sleep"
    ):
        assert (
            await engine._verify_worker_recovery(
                Restarted(),
                "127.0.0.1",
                9999,
                "same-process",
            )
            is True
        )

async def test_ssh_fallback_uses_stored_instance_id_when_api_is_already_down(tmp_path):
    private_key = tmp_path / "lattice_ed25519"
    known_hosts = tmp_path / "known_hosts"
    private_key.write_text("private")
    known_hosts.write_text("known host")

    class OfflineThenHealthy:
        def __init__(self):
            self.health_calls = 0

        async def post(self, *_args, **_kwargs):
            raise httpx.ConnectError("worker API offline")

        async def get(self, *_args, **_kwargs):
            self.health_calls += 1
            if self.health_calls == 1:
                raise httpx.ConnectError("worker API offline")
            return SimpleNamespace(
                status_code=200,
                json=lambda: {"status": "healthy", "instance_id": "new-process"},
            )

        async def aclose(self):
            return None

    engine = AutoHealEngine(ssh_runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""))
    config = SimpleNamespace(master=SimpleNamespace(ip="127.0.0.1"), wire_format=SimpleNamespace(port=9999))

    with patch("lattice.healing.engine.SSH_PRIVATE_KEY", private_key), \
         patch("lattice.healing.engine.SSH_KNOWN_HOSTS", known_hosts), \
         patch("lattice.healing.engine.LatticeHTTPClient", return_value=OfflineThenHealthy()), \
         patch("lattice.healing.engine.load_config", return_value=config), \
         patch("lattice.healing.engine.asyncio.sleep"), \
         patch("lattice.healing.engine.log_event"), \
         patch.object(engine.audit, "log_entry", return_value=True), \
         patch("lattice.healing.engine.get_async_db_connection") as get_conn:
        conn = get_conn.return_value
        cursor = conn.execute.return_value
        cursor.fetchone.return_value = ("127.0.0.1", "test-worker", "testuser", "old-process")
        assert await engine._attempt_heal_locked(1, "lattice-worker", "restart", {}) is True
