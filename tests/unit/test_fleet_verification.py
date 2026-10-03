import asyncio
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from lattice.core.migrations import run_migrations
from lattice.verification import alerts as alert_verify
from lattice.verification import backup as backup_verify
from lattice.verification import fleet as fleet_verify
from lattice.verification import node as node_verify


def _fresh_db(tmp_path, monkeypatch):
    path = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(path))
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    run_migrations(conn)
    conn.commit()
    conn.close()
    return path


def test_local_verification_allows_only_proven_stale_failed_units(monkeypatch):
    monkeypatch.setattr(node_verify, "load_node_identity", lambda: SimpleNamespace(node_id="node-1"))
    monkeypatch.setattr(node_verify, "_master_core_blockers", lambda: ([], {"db": "healthy"}))
    monkeypatch.setattr(node_verify, "scan_health", lambda **kwargs: [{"code": "systemd.failed", "severity": "attention", "subject": "Failed systemd unit(s)", "detail": "old"}])
    monkeypatch.setattr(node_verify, "_failed_systemd_units", lambda: ["old.service"])
    monkeypatch.setattr(node_verify, "_stale_unit_proof", lambda unit, node_id: (True, "proved recovered"))
    monkeypatch.setattr(node_verify, "_network_state", lambda: "healthy")
    monkeypatch.setattr(
        node_verify,
        "local_care_observation",
        lambda **kwargs: {"status": "attention"},
    )
    monkeypatch.setattr(
        node_verify,
        "load_config",
        lambda: SimpleNamespace(care=SimpleNamespace(disk_warning_percent=80, disk_critical_percent=90)),
    )

    report = node_verify.collect_local_verification("master")

    assert report["status"] == "healthy"
    assert report["stale_failed_units"][0]["unit"] == "old.service"
    assert report["stored_care"]["status"] == "attention"


def test_local_verification_blocks_unknown_failed_units(monkeypatch):
    monkeypatch.setattr(node_verify, "load_node_identity", lambda: SimpleNamespace(node_id="node-1"))
    monkeypatch.setattr(node_verify, "_master_core_blockers", lambda: ([], {}))
    monkeypatch.setattr(node_verify, "scan_health", lambda **kwargs: [])
    monkeypatch.setattr(node_verify, "_failed_systemd_units", lambda: ["mystery.service"])
    monkeypatch.setattr(node_verify, "_stale_unit_proof", lambda unit, node_id: (False, "no verifier"))
    monkeypatch.setattr(node_verify, "_network_state", lambda: "healthy")
    monkeypatch.setattr(node_verify, "local_care_observation", lambda **kwargs: {"status": "healthy"})
    monkeypatch.setattr(
        node_verify,
        "load_config",
        lambda: SimpleNamespace(care=SimpleNamespace(disk_warning_percent=80, disk_critical_percent=90)),
    )

    report = node_verify.collect_local_verification("master")

    assert report["status"] == "blocked"
    assert report["blocking_failed_units"][0]["unit"] == "mystery.service"


def test_verify_fleet_includes_every_active_node_and_stale_care(monkeypatch):
    async def fake_collect():
        return 7, [
            {"node_id": "m", "hostname": "master", "role": "master", "status": "healthy", "blockers": [], "stale_failed_units": [], "stored_care": {"status": "healthy"}},
            {"node_id": "w1", "hostname": "worker-1", "role": "worker", "status": "healthy", "blockers": [], "stale_failed_units": [], "stored_care": {"status": "attention"}},
            {"node_id": "w2", "hostname": "worker-2", "role": "worker", "status": "healthy", "blockers": [], "stale_failed_units": [], "stored_care": {"status": "healthy"}},
        ]
    monkeypatch.setattr(fleet_verify, "_collect_fleet", fake_collect)
    monkeypatch.setattr(fleet_verify, "evaluate_active_alerts", lambda reports: [])

    report = fleet_verify.verify_fleet()

    assert [n["hostname"] for n in report["nodes"]] == ["master", "worker-1", "worker-2"]
    assert report["status"] == "pass"
    assert report["stale_care_count"] == 1
    assert report["can_clear"] is True


def test_verify_fleet_blocks_when_any_active_node_is_unreachable(monkeypatch):
    async def fake_collect():
        return 8, [
            {"node_id": "m", "hostname": "master", "role": "master", "status": "healthy", "blockers": [], "stale_failed_units": [], "stored_care": {"status": "healthy"}},
            {"node_id": "w1", "hostname": "worker-1", "role": "worker", "status": "blocked", "blockers": ["authenticated live verification failed: timeout"], "stale_failed_units": [], "stored_care": {"status": "stale"}},
        ]
    monkeypatch.setattr(fleet_verify, "_collect_fleet", fake_collect)
    monkeypatch.setattr(fleet_verify, "evaluate_active_alerts", lambda reports: [])

    report = fleet_verify.verify_fleet()

    assert report["status"] == "blocked"
    assert report["can_clear"] is False
    assert "worker-1" in report["blockers"][0]


def test_unknown_alert_type_can_never_be_cleared():
    row = {
        "id": 1,
        "worker_id": None,
        "hostname": None,
        "event_type": "future.new_alert_type",
        "details": "{}",
    }
    recovered, reason = alert_verify._event_recovery(row, {"master": {"role": "master", "status": "healthy"}})
    assert recovered is None
    assert "no recovery verifier" in reason


def test_connectivity_only_backup_maintenance_failure_can_be_proven_recovered(tmp_path, monkeypatch):
    path = _fresh_db(tmp_path, monkeypatch)
    now = datetime.now(timezone.utc)
    source = "11111111-1111-4111-8111-111111111111"
    target_node = "22222222-2222-4222-8222-222222222222"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (source, "master", "master", "user", 1000, 1000),
    )
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (target_node, "backup-node", "worker", "user", 1000, 1000),
    )
    target_id = conn.execute(
        """INSERT INTO backup_targets(target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,repository_root)
           VALUES('target-uuid','Backup',?,'remote_storage','disk-uuid','/mnt/backup')""",
        (target_node,),
    ).lastrowid
    job_id = conn.execute(
        """INSERT INTO backup_jobs(job_uuid,source_node_id,target_id,source_path)
           VALUES('job-uuid',?,?, '/home/user')""",
        (source, target_id),
    ).lastrowid
    failed_at = now - timedelta(hours=2)
    succeeded_at = now - timedelta(hours=1)
    conn.execute(
        """INSERT INTO backup_maintenance_state(job_id,last_result,last_error,updated_at)
           VALUES(?, 'failed', 'ssh: No route to host', ?)""",
        (job_id, failed_at.isoformat()),
    )
    conn.execute(
        """INSERT INTO backup_runs(job_id,started_at,finished_at,result)
           VALUES(?,?,?,'successful')""",
        (job_id, (succeeded_at - timedelta(minutes=5)).isoformat(), succeeded_at.isoformat()),
    )
    conn.execute(
        """INSERT INTO backup_job_observations(
               job_id,observer_node_id,state,last_success_at,last_result,failure_streak,
               credential_missing,last_reported_at)
           VALUES(?,?, 'healthy',?, 'successful',0,0,?)""",
        (job_id, source, succeeded_at.isoformat(), now.isoformat()),
    )
    conn.commit()
    conn.close()

    recovered, reason = backup_verify.maintenance_failure_recovered(job_id)

    assert recovered is True
    assert "transport failure recovered" in reason


def test_non_connectivity_maintenance_failure_is_not_guessed_recovered(tmp_path, monkeypatch):
    path = _fresh_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    source = "33333333-3333-4333-8333-333333333333"
    target_node = "44444444-4444-4444-8444-444444444444"
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (source, "master-2", "master", "user", 1000, 1000),
    )
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (target_node, "backup-2", "worker", "user", 1000, 1000),
    )
    target_id = conn.execute(
        """INSERT INTO backup_targets(target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,repository_root)
           VALUES('target-uuid-2','Backup',?,'remote_storage','disk-uuid-2','/mnt/backup')""",
        (target_node,),
    ).lastrowid
    job_id = conn.execute(
        """INSERT INTO backup_jobs(job_uuid,source_node_id,target_id,source_path)
           VALUES('job-uuid-2',?,?, '/home/user')""",
        (source, target_id),
    ).lastrowid
    conn.execute(
        """INSERT INTO backup_maintenance_state(job_id,last_result,last_error,updated_at)
           VALUES(?, 'failed', 'repository check reported corruption', ?)""",
        (job_id, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()

    recovered, reason = backup_verify.maintenance_failure_recovered(job_id)

    assert recovered is False
    assert "successful maintenance verification" in reason


def test_installer_grants_only_exact_verification_helper_verbs():
    from pathlib import Path

    text = Path("deploy/install.sh").read_text()
    assert "lattice-verification-control verify-fleet" in text
    assert "lattice-verification-control clear-resolved" in text
    assert "lattice-verification-control clear-local" in text
    assert "lattice-verification-control *" not in text


def test_clear_local_resets_only_units_from_fresh_verification(monkeypatch):
    before = {
        "status": "healthy",
        "blockers": [],
        "stale_failed_units": [{"unit": "approved.service", "reason": "proved"}],
        "live_care_findings": [{"code": "systemd.failed"}],
        "hostname": "node-a",
    }
    after = {
        "status": "healthy",
        "blockers": [],
        "stale_failed_units": [],
        "live_care_findings": [],
        "hostname": "node-a",
    }
    reports = iter([before, after])
    monkeypatch.setattr(node_verify.os, "geteuid", lambda: 0)
    monkeypatch.setattr(node_verify, "collect_local_verification", lambda role=None: next(reports))
    calls = []
    monkeypatch.setattr(
        node_verify,
        "_run",
        lambda command, timeout=15: calls.append(command) or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(node_verify, "_record_clean_care_snapshot", lambda: 11)

    result = node_verify.clear_local_resolved_state("worker")

    assert calls == [["/usr/bin/systemctl", "reset-failed", "approved.service"]]
    assert result["reset_units"] == ["approved.service"]
    assert result["care_run_id"] == 11


def test_clear_local_refuses_before_any_systemd_change_when_blocked(monkeypatch):
    monkeypatch.setattr(node_verify.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        node_verify,
        "collect_local_verification",
        lambda role=None: {"status": "blocked", "blockers": ["real problem"], "stale_failed_units": []},
    )
    calls = []
    monkeypatch.setattr(node_verify, "_run", lambda *args, **kwargs: calls.append(args))

    import pytest
    with pytest.raises(node_verify.VerificationError, match="real problem"):
        node_verify.clear_local_resolved_state("worker")
    assert calls == []


def test_authenticated_worker_care_snapshot_refreshes_master_immediately(tmp_path, monkeypatch):
    path = _fresh_db(tmp_path, monkeypatch)
    node_id = "55555555-5555-4555-8555-555555555555"
    conn = sqlite3.connect(path)
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (node_id, "worker-a", "worker", "user", 1000, 1000),
    )
    conn.commit()
    conn.close()
    care = {
        "node_id": node_id,
        "hostname": "worker-a",
        "status": "healthy",
        "last_run_at": datetime.now(timezone.utc).isoformat(),
        "bytes_reclaimed": 0,
        "attention_count": 0,
        "critical_count": 0,
        "deferred_reason": None,
        "findings": [],
    }

    fleet_verify._refresh_replicated_care([
        {"node_id": node_id, "hostname": "worker-a", "role": "worker", "stored_care": care}
    ])

    conn = sqlite3.connect(path)
    row = conn.execute(
        "SELECT status,attention_count,critical_count FROM care_observations WHERE node_id=?",
        (node_id,),
    ).fetchone()
    conn.close()
    assert row == ("healthy", 0, 0)


def test_resolve_verified_alerts_writes_resolution_event(tmp_path, monkeypatch):
    path = _fresh_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    event_id = conn.execute(
        """INSERT INTO events(timestamp,worker_id,type,severity,message)
           VALUES(?,NULL,'backup.verification_failed','critical','old failure')""",
        (datetime.now(timezone.utc).isoformat(),),
    ).lastrowid
    alert_id = conn.execute(
        """INSERT INTO alerts(worker_id,severity,title,message,trigger_event_id,fired_at)
           VALUES(NULL,'critical','Backup maintenance failed','old failure',?,?)""",
        (event_id, datetime.now(timezone.utc).isoformat()),
    ).lastrowid
    conn.commit()
    conn.close()

    report = {
        "alerts": [{
            "id": alert_id,
            "event_type": "backup.verification_failed",
            "verdict": "resolved",
            "reason": "newer successful backup proved recovery",
        }]
    }
    assert fleet_verify._resolve_verified_alerts(report) == 1

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """SELECT a.resolved_at,e.type AS resolution_type
           FROM alerts a JOIN events e ON e.id=a.resolution_event_id
           WHERE a.id=?""",
        (alert_id,),
    ).fetchone()
    conn.close()
    assert row["resolved_at"] is not None
    assert row["resolution_type"] == "verification.recovered"
