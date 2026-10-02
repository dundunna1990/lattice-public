from datetime import datetime, timedelta, timezone
import sqlite3
import uuid

from lattice.backup import alerts
from lattice.core.migrations import run_migrations


def _setup(tmp_path, monkeypatch, *, age_hours=25, failure_streak=0,
           maintenance_result=None, credential_missing=False,
           target_present=True, free_percent=50.0, missing_hours=0):
    db = tmp_path / 'state.sqlite'
    monkeypatch.setenv('LATTICE_DB_PATH', str(db))
    monkeypatch.setattr(alerts, '_refresh_local_master_observations', lambda _now: None)
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    run_migrations(conn)
    now = datetime(2026, 9, 3, 12, tzinfo=timezone.utc)
    source = str(uuid.uuid4())
    target_node = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO workers(hostname,status,ip,ssh_user) VALUES('worker-node','healthy','10.0.0.2','workeruser')"
    )
    worker_id = conn.execute("SELECT id FROM workers WHERE hostname='worker-node'").fetchone()[0]
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,worker_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?,?, 'active')""",
        (source, worker_id, 'worker-node', 'worker', 'workeruser', 1000, 1000),
    )
    conn.execute(
        """INSERT INTO fleet_nodes(node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?, 'active')""",
        (target_node, 'backup-node', 'worker', 'backupuser', 1000, 1000),
    )
    target_uuid = str(uuid.uuid4())
    cursor = conn.execute(
        """INSERT INTO backup_targets(target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,repository_root)
           VALUES(?,?,?,?,?,?)""",
        (target_uuid, 'Backup Drive', target_node, 'remote_storage', 'disk-uuid', '/mnt/backup/LatticeBackups'),
    )
    target_id = cursor.lastrowid
    job_uuid = str(uuid.uuid4())
    created = (now - timedelta(hours=max(age_hours, 1))).isoformat()
    cursor = conn.execute(
        """INSERT INTO backup_jobs(job_uuid,source_node_id,target_id,source_path,created_at)
           VALUES(?,?,?,?,?)""",
        (job_uuid, source, target_id, '/home/workeruser', created),
    )
    job_id = cursor.lastrowid
    last_success = (now - timedelta(hours=age_hours)).isoformat()
    conn.execute(
        """INSERT INTO backup_job_observations(
               job_id,observer_node_id,state,last_success_at,last_result,failure_streak,
               problem_since,maintenance_result,maintenance_error,credential_missing,last_reported_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (
            job_id, source, 'pending' if failure_streak else 'healthy',
            last_success, 'failed' if failure_streak else 'successful', failure_streak,
            (now - timedelta(hours=2)).isoformat() if failure_streak else None,
            maintenance_result, 'verification failed' if maintenance_result == 'failed' else None,
            1 if credential_missing else 0,
            now.isoformat(),
        ),
    )
    total = 1000
    free = int(total * free_percent / 100.0)
    problem_since = (
        (now - timedelta(hours=missing_hours)).isoformat()
        if not target_present else None
    )
    conn.execute(
        """INSERT INTO backup_target_observations(
               target_id,observer_node_id,present,problem_since,filesystem_uuid,mountpoint,
               total_bytes,free_bytes,health,last_reported_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (
            target_id, target_node, 1 if target_present else 0, problem_since,
            'disk-uuid' if target_present else None,
            '/mnt/backup' if target_present else None,
            total if target_present else None, free if target_present else None,
            'healthy' if target_present else 'offline', now.isoformat(),
        ),
    )
    conn.commit(); conn.close()
    calls = []
    monkeypatch.setattr(alerts, '_set_incident', lambda **kwargs: calls.append(kwargs))
    return now, calls


def _active(calls, prefix):
    return [item for item in calls if item['active'] and item['title'].startswith(prefix)]


def test_overdue_warning_at_24_hours(tmp_path, monkeypatch):
    now, calls = _setup(tmp_path, monkeypatch, age_hours=25)
    alerts.sync_backup_alerts(now=now)
    assert len(_active(calls, 'Backup overdue:')) == 1
    assert _active(calls, 'Backup severely overdue:') == []


def test_severe_overdue_replaces_warning_at_48_hours(tmp_path, monkeypatch):
    now, calls = _setup(tmp_path, monkeypatch, age_hours=50)
    alerts.sync_backup_alerts(now=now)
    assert _active(calls, 'Backup overdue:') == []
    assert len(_active(calls, 'Backup severely overdue:')) == 1


def test_repeated_failure_and_maintenance_failure_alert(tmp_path, monkeypatch):
    now, calls = _setup(
        tmp_path, monkeypatch, age_hours=2, failure_streak=3,
        maintenance_result='failed',
    )
    alerts.sync_backup_alerts(now=now)
    assert len(_active(calls, 'Backup repeatedly failing:')) == 1
    assert len(_active(calls, 'Backup maintenance failed:')) == 1
    assert _active(calls, 'Backup overdue:') == []


def test_low_space_alerts_below_reserve(tmp_path, monkeypatch):
    now, calls = _setup(tmp_path, monkeypatch, age_hours=2, free_percent=15)
    alerts.sync_backup_alerts(now=now)
    active = _active(calls, 'Backup target low space:')
    assert len(active) == 1
    assert active[0]['severity'] == 'warning'


def test_missing_target_waits_for_persistent_window(tmp_path, monkeypatch):
    now, calls = _setup(
        tmp_path, monkeypatch, age_hours=2, target_present=False, missing_hours=25,
    )
    alerts.sync_backup_alerts(now=now)
    assert len(_active(calls, 'Backup target missing:')) == 1


def test_short_missing_target_does_not_alert(tmp_path, monkeypatch):
    now, calls = _setup(
        tmp_path, monkeypatch, age_hours=2, target_present=False, missing_hours=1,
    )
    alerts.sync_backup_alerts(now=now)
    assert _active(calls, 'Backup target missing:') == []


def test_missing_credential_is_immediate_critical_alert(tmp_path, monkeypatch):
    now, calls = _setup(
        tmp_path, monkeypatch, age_hours=2, credential_missing=True,
    )
    alerts.sync_backup_alerts(now=now)
    active = _active(calls, 'Backup credential missing:')
    assert len(active) == 1
    assert active[0]['severity'] == 'critical'
    assert active[0]['event_type'] == 'backup.credential_missing'


def test_present_credential_resolves_missing_credential_incident(tmp_path, monkeypatch):
    now, calls = _setup(
        tmp_path, monkeypatch, age_hours=2, credential_missing=False,
    )
    alerts.sync_backup_alerts(now=now)
    matching = [item for item in calls if item['title'].startswith('Backup credential missing:')]
    assert len(matching) == 1
    assert matching[0]['active'] is False
