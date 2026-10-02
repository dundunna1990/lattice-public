"""Tests for the safety checks shared by all auto-heal action paths."""
from types import SimpleNamespace
from unittest.mock import patch

from lattice.healing.engine import AutoHealEngine


async def test_engine_dry_run_never_contacts_a_worker():
    engine = AutoHealEngine()
    config = SimpleNamespace(daemon=SimpleNamespace(dry_run=True))

    with patch.object(engine, "should_heal", return_value=True):
        with patch.object(engine.audit, "log_entry") as log_entry:
            with patch("lattice.healing.engine.load_config", return_value=config):
                with patch("lattice.healing.engine.log_event"):
                    with patch("lattice.healing.engine.get_config_value", return_value="automatic"):
                        with patch("lattice.healing.engine.reserve_restart_attempt", return_value=True):
                            with patch("lattice.healing.engine.LatticeHTTPClient") as client:
                                assert await engine.attempt_heal(1, "lattice-worker", "restart") is False

    log_entry.assert_called_once()
    assert log_entry.call_args.kwargs["result"] == "dry_run"
    client.assert_not_called()
