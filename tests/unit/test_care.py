import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from lattice.care import runner
from lattice.care.observations import normalize_care_observation
from lattice.care.safety import CareSafetyError, assert_allowed_delete
from lattice.core.migrations import run_migrations


def _db(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(path))
    monkeypatch.setenv("LATTICE_CARE_LOCK_PATH", str(tmp_path / "care.lock"))
    conn = sqlite3.connect(path)
    run_migrations(conn)
    conn.close()
    return path


def test_schema_contains_daily_care_tables(tmp_path, monkeypatch):
    path = _db(tmp_path, monkeypatch)
    conn = sqlite3.connect(path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert {"care_runs", "care_actions", "care_findings", "care_observations"} <= tables


def test_safety_refuses_home_root_and_symlink(tmp_path):
    for path in (Path("/home/user/file"), Path("/root/secret"), Path("/mnt/lattice/node/file")):
        with pytest.raises(CareSafetyError):
            assert_allowed_delete(path, allowed_parent=path.parent)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target = allowed / "target"
    target.write_text("x")
    link = allowed / "link"
    link.symlink_to(target)
    with pytest.raises(CareSafetyError, match="symbolic"):
        assert_allowed_delete(link, allowed_parent=allowed.resolve())


def test_crash_cleanup_only_removes_old_direct_crash_files(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    crash = tmp_path / "crash"
    crash.mkdir()
    old = crash / "old.crash"
    old.write_bytes(b"x" * 11)
    os.utime(old, (time.time() - runner.CRASH_MAX_AGE_SECONDS - 5,) * 2)
    recent = crash / "recent.crash"
    recent.write_text("keep")
    other = crash / "notes.txt"
    other.write_text("keep")
    target = tmp_path / "outside"
    target.write_text("outside")
    (crash / "escape.crash").symlink_to(target)
    monkeypatch.setattr(runner, "CRASH_ROOT", crash)
    conn = sqlite3.connect(tmp_path / "state.sqlite")
    run_id = conn.execute(
        "INSERT INTO care_runs(started_at,trigger,status) VALUES('now','manual','attention')"
    ).lastrowid
    conn.commit()
    conn.close()

    reclaimed = runner._cleanup_crash_reports(run_id)

    assert reclaimed == 11
    assert not old.exists()
    assert recent.exists()
    assert other.exists()
    assert target.read_text() == "outside"


def test_mixed_autoremove_candidates_are_refused(monkeypatch):
    calls = []
    records = []
    responses = iter(
        [
            SimpleNamespace(
                returncode=0, stdout="Remv linux-image-1\nRemv ordinary-package\n", stderr=""
            ),
        ]
    )
    monkeypatch.setattr(
        runner, "_run", lambda *args, **kwargs: calls.append(args[0]) or next(responses)
    )
    monkeypatch.setattr(
        runner,
        "_record_action",
        lambda run_id, name, result, **kwargs: records.append((name, result, kwargs.get("detail"))),
    )

    runner._kernel_cleanup(7)

    assert len(calls) == 1
    assert records[0][0:2] == ("old_kernels", "deferred")
    assert "non-kernel" in records[0][2]


def test_security_update_policy_rejects_normal_updates(tmp_path):
    config = tmp_path / "50unattended-upgrades"
    config.write_text(
        "Unattended-Upgrade::Allowed-Origins {\n"
        '  "${distro_id}:${distro_codename}-security";\n'
        '  "${distro_id}:${distro_codename}-updates";\n'
        "};\n"
    )
    assert runner._unattended_policy_is_security_only(config) is False
    config.write_text(
        'Unattended-Upgrade::Allowed-Origins {\n  "${distro_id}:${distro_codename}-security";\n};\n'
    )
    assert runner._unattended_policy_is_security_only(config) is True


def test_run_defers_mutations_on_low_battery(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        runner,
        "load_config",
        lambda: SimpleNamespace(
            care=SimpleNamespace(
                enabled=True,
                battery_defer_percent=30,
                disk_warning_percent=80,
                disk_critical_percent=90,
                stale_crash_cleanup=True,
                apt_autoclean=True,
                journal_vacuum=True,
                flatpak_unused_cleanup=True,
                old_kernel_cleanup=True,
                security_updates=True,
            )
        ),
    )
    monkeypatch.setattr(runner, "scan_health", lambda **kwargs: [])
    monkeypatch.setattr(
        runner, "battery_should_defer", lambda **kwargs: (True, "Battery 20% and unplugged")
    )
    monkeypatch.setattr(runner, "backup_work_active", lambda: False)
    for name in (
        "_cleanup_crash_reports",
        "_apt_autoclean",
        "_journal_vacuum",
        "_flatpak_unused",
        "_kernel_cleanup",
        "_security_updates",
    ):
        monkeypatch.setattr(
            runner, name, lambda *args, _name=name, **kwargs: pytest.fail(f"{_name} should not run")
        )

    result = runner.run_daily_care(trigger="manual")

    assert result["status"] == "attention"
    assert result["deferred_reason"] == "Battery 20% and unplugged"


def test_care_observation_rejects_wrong_node_and_bad_fields():
    good = {
        "node_id": "node-1",
        "hostname": "worker",
        "status": "healthy",
        "last_run_at": None,
        "bytes_reclaimed": 0,
        "attention_count": 0,
        "critical_count": 0,
        "deferred_reason": None,
        "findings": [],
    }
    assert normalize_care_observation(good, "node-1")["status"] == "healthy"
    with pytest.raises(ValueError, match="identity"):
        normalize_care_observation(good, "node-2")
    bad = dict(good)
    bad["extra"] = "no"
    with pytest.raises(ValueError, match="unsupported"):
        normalize_care_observation(bad, "node-1")


def test_daily_care_units_and_helper_are_narrow():
    service = Path("deploy/systemd/lattice-care.service").read_text()
    timer = Path("deploy/systemd/lattice-care.timer").read_text()
    helper = Path("deploy/lattice-care-control").read_text()
    installer = Path("deploy/install.sh").read_text()
    assert "OnCalendar=*-*-* 03:17:00" in timer
    assert "RandomizedDelaySec=45m" in timer
    assert "Persistent=true" in timer
    assert "Type=oneshot" in service
    assert "TimeoutStartSec=30min" in service
    assert "export LATTICE_CONFIG_PATH=/etc/lattice/lattice.toml" in helper
    assert "export LATTICE_DB_PATH=/var/lib/lattice/state.sqlite" in helper
    assert "export LATTICE_SOCKET_PATH=/run/lattice/master.sock" in helper
    assert "python -I -m lattice.care.control" in helper
    assert "lattice-care-control run" in installer
    assert "lattice-care.timer" in installer


def test_care_run_lock_refuses_overlap(tmp_path, monkeypatch):
    from lattice.care.safety import care_run_lock

    monkeypatch.setenv("LATTICE_CARE_LOCK_PATH", str(tmp_path / "care.lock"))
    with care_run_lock(), pytest.raises(CareSafetyError, match="already running"):
        with care_run_lock():
            pass


def test_local_observation_is_stale_before_care_schema_exists(tmp_path, monkeypatch):
    from lattice.care.observations import local_care_observation

    path = tmp_path / "old.sqlite"
    sqlite3.connect(path).close()
    monkeypatch.setenv("LATTICE_DB_PATH", str(path))
    result = local_care_observation(node_id="node-1")
    assert result["status"] == "stale"
    assert result["node_id"] == "node-1"


def test_run_records_plan_before_deferred_mutations(tmp_path, monkeypatch):
    db = _db(tmp_path, monkeypatch)
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        runner,
        "load_config",
        lambda: SimpleNamespace(
            care=SimpleNamespace(
                enabled=True,
                battery_defer_percent=30,
                disk_warning_percent=80,
                disk_critical_percent=90,
                stale_crash_cleanup=True,
                apt_autoclean=True,
                journal_vacuum=True,
                flatpak_unused_cleanup=True,
                old_kernel_cleanup=True,
                security_updates=True,
            )
        ),
    )
    monkeypatch.setattr(runner, "scan_health", lambda **kwargs: [])
    monkeypatch.setattr(
        runner, "battery_should_defer", lambda **kwargs: (True, "Battery 20% and unplugged")
    )
    monkeypatch.setattr(runner, "backup_work_active", lambda: False)

    result = runner.run_daily_care(trigger="manual")
    conn = sqlite3.connect(db)
    plan = conn.execute(
        "SELECT plan_json FROM care_runs WHERE id=?", (result["run_id"],)
    ).fetchone()[0]
    conn.close()
    assert "health_scan" in plan
    assert "mutating_phase: deferred" in plan


def test_failed_maintenance_action_makes_run_attention(tmp_path, monkeypatch):
    _db(tmp_path, monkeypatch)
    monkeypatch.setattr(runner.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        runner,
        "load_config",
        lambda: SimpleNamespace(
            care=SimpleNamespace(
                enabled=True,
                battery_defer_percent=30,
                disk_warning_percent=80,
                disk_critical_percent=90,
                stale_crash_cleanup=False,
                apt_autoclean=True,
                journal_vacuum=False,
                flatpak_unused_cleanup=False,
                old_kernel_cleanup=False,
                security_updates=False,
            )
        ),
    )
    monkeypatch.setattr(runner, "scan_health", lambda **kwargs: [])
    monkeypatch.setattr(runner, "battery_should_defer", lambda **kwargs: (False, None))
    monkeypatch.setattr(runner, "backup_work_active", lambda: False)

    def fail_autoclean(run_id):
        runner._record_action(run_id, "apt_autoclean", "failed", detail="fixture failure")

    monkeypatch.setattr(runner, "_apt_autoclean", fail_autoclean)

    result = runner.run_daily_care(trigger="manual")

    assert result["status"] == "attention"
    assert result["attention_count"] == 1
