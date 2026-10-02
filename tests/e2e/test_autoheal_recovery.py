"""Real auto-heal and bounded-failure tests."""
from __future__ import annotations

import time

import pytest

from .conftest import WORKER_HOST, run, ssh

pytestmark = [pytest.mark.e2e, pytest.mark.destructive_e2e, pytest.mark.autoheal_live_e2e]


def _worker_status() -> str:
    result = run(["sg", "lattice-operator", "-c",
                  f"/opt/lattice/venv/bin/lattice workers get {WORKER_HOST}"], timeout=15)
    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        if line.startswith("Status: "):
            return line.split(":", 1)[1].strip()
    pytest.fail("operator output omitted Worker status")


def _wait_status(expected: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    seen: list[str] = []
    while time.monotonic() < deadline:
        try:
            status = _worker_status()
            seen.append(status)
            if status == expected:
                return
        except AssertionError:
            pass
        time.sleep(2)
    pytest.fail(f"Worker never reached {expected!r}; observed={seen[-12:]}")


def test_e2e_heal_001_worker_stop_is_detected_and_healed():
    stopped = ssh(
        WORKER_HOST,
        "sudo -n systemctl stop lattice-worker.service",
        timeout=30,
    )
    assert stopped.returncode == 0, stopped.stderr

    # The Master must first observe a real failure; a test that only checks
    # the final healthy state could pass without exercising detection/healing.
    deadline = time.monotonic() + 90
    saw_failure = False
    while time.monotonic() < deadline:
        status = _worker_status()
        if status in {"degraded", "down"}:
            saw_failure = True
            break
        time.sleep(2)
    assert saw_failure, "Master never exposed Worker failure after daemon stop"

    _wait_status("healthy", timeout=120)
    active = ssh(WORKER_HOST, "systemctl is-active lattice-worker.service")
    assert active.returncode == 0
    assert active.stdout.strip() == "active"


def test_e2e_heal_002_recovery_does_not_leave_active_alerts():
    _wait_status("healthy", timeout=30)
    alerts = run(["sg", "lattice-operator", "-c",
                  "/opt/lattice/venv/bin/lattice alerts list"], timeout=15)
    assert alerts.returncode == 0, alerts.stderr
    assert WORKER_HOST not in alerts.stdout or "resolved" in alerts.stdout.lower()

def test_e2e_heal_003_restart_budget_prevents_restart_storm():
    """E2E-HEAL-003: repeated failed repairs must stop at the real restart budget."""
    baseline_query = (
        "import sqlite3; "
        "c=sqlite3.connect('/var/lib/lattice/state.sqlite'); "
        "print(c.execute('SELECT COALESCE(MAX(id),0) FROM events').fetchone()[0])"
    )
    baseline = run(
        ["sudo", "-n", "/opt/lattice/venv/bin/python", "-c", baseline_query],
        timeout=10,
    )
    assert baseline.returncode == 0, baseline.stderr
    baseline_event_id = int(baseline.stdout.strip())

    def budget_state():
        query = (
            "import sqlite3; "
            "from datetime import datetime,timedelta,timezone; "
            "c=sqlite3.connect('/var/lib/lattice/state.sqlite'); "
            "wid=c.execute("
            "\"SELECT id FROM workers WHERE hostname=? AND removed_at IS NULL\","
            f"({WORKER_HOST!r},)).fetchone()[0]; "
            "cutoff=(datetime.now(timezone.utc)-timedelta(minutes=15)).isoformat(); "
            "count=c.execute("
            "\"SELECT COUNT(*) FROM healing_attempts "
            "WHERE worker_id=? AND service='lattice-worker' "
            "AND action='restart' AND started_at>=?\","
            "(wid,cutoff)).fetchone()[0]; "
            "blocked=c.execute("
            "\"SELECT 1 FROM events "
            "WHERE worker_id=? AND id>? "
            "AND type='autoheal.detected' "
            "AND message LIKE '%two-restart limit%' "
            "ORDER BY id DESC LIMIT 1\","
            f"(wid,{baseline_event_id})).fetchone(); "
            "print(f'{count} {1 if blocked else 0}')"
        )
        result = run(
            ["sudo", "-n", "/opt/lattice/venv/bin/python", "-c", query],
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        count_text, blocked_text = result.stdout.strip().split()
        return int(count_text), blocked_text == "1"

    try:
        masked = ssh(
            WORKER_HOST,
            "sudo -n systemctl mask --runtime lattice-worker.service "
            "&& sudo -n systemctl stop lattice-worker.service",
            timeout=30,
        )
        assert masked.returncode == 0, masked.stderr

        deadline = time.monotonic() + 180
        observed = []
        blocked = False

        while time.monotonic() < deadline:
            count, blocked = budget_state()
            observed.append(count)

            assert count <= 2, (
                "restart storm exceeded the two-attempt safety budget: "
                f"{observed}"
            )

            if blocked:
                break

            time.sleep(3)

        assert blocked, (
            "Master never reported that the two-restart / 15-minute "
            f"safety budget blocked further repairs; observed={observed}"
        )

        blocked_count, _ = budget_state()

        # Keep the Worker unrestartable for another health-check window.
        # The attempt count must not continue growing.
        time.sleep(20)

        later_count, still_blocked = budget_state()

        assert still_blocked
        assert later_count == blocked_count
        assert later_count <= 2

    finally:
        ssh(
            WORKER_HOST,
            "sudo -n systemctl unmask lattice-worker.service; "
            "sudo -n systemctl start lattice-worker.service",
            timeout=30,
        )
        _wait_status("healthy", timeout=120)
