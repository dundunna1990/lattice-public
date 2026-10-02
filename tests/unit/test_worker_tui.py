from types import SimpleNamespace
import sqlite3

import pytest

from lattice.cli import tui
from lattice.core.migrations import run_migrations
import lattice.cli.commands.wipe as wipe_cmd
import lattice.cli.commands.workers as workers_cmd
from lattice.onboarding import PairingError
from lattice.pairing import pair_worker


def _open_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _worker_db(tmp_path):
    db = tmp_path / "worker-tui.sqlite"
    conn = _open_db(db)
    run_migrations(conn)

    nodes = [
        ("worker-id", "worker-node", "worker", "workeruser", 1000, 1000, "active"),
        ("master-id", "master-node", "master", "masteruser", 1000, 1000, "active"),
        ("backup-node-id", "backup-node", "worker", "backupuser", 1000, 1000, "active"),
    ]
    conn.executemany(
        """INSERT INTO fleet_nodes(
               node_id,hostname,role,main_user,main_uid,main_gid,membership_state)
           VALUES(?,?,?,?,?,?,?)""",
        nodes,
    )
    conn.executemany(
        """INSERT INTO shell_connection_state(
               peer_node_id,hostname,state,selected_ip,failure_count)
           VALUES(?,?,?,?,?)""",
        [
            ("master-id", "master-id", "connected", "10.77.0.200", 0),
            ("backup-node-id", "backup-node-id", "connected", "10.77.0.202", 0),
        ],
    )
    conn.execute(
        """INSERT INTO backup_targets(
               target_uuid,friendly_name,host_node_id,target_type,filesystem_uuid,
               repository_root,repository_relative_path,enabled)
           VALUES(?,?,?,?,?,?,?,1)""",
        (
            "target-uuid",
            "backup-node Backup Drive",
            "backup-node-id",
            "remote_storage",
            "disk-uuid",
            "/mnt/backup",
            "LatticeBackups",
        ),
    )
    target_id = conn.execute("SELECT id FROM backup_targets").fetchone()[0]
    conn.execute(
        """INSERT INTO backup_jobs(
               job_uuid,source_node_id,target_id,source_path,enabled,paused)
           VALUES(?,?,?,?,1,0)""",
        ("job-uuid", "worker-id", target_id, "/home/workeruser"),
    )
    conn.commit()
    conn.close()
    return db


def test_worker_status_uses_real_local_worker_truth(tmp_path, monkeypatch):
    db = _worker_db(tmp_path)

    monkeypatch.setattr(tui, "get_db_connection", lambda: _open_db(db))
    monkeypatch.setattr(tui.socket, "gethostname", lambda: "worker-node")
    monkeypatch.setattr(tui, "_service_active", lambda _unit: "running")
    monkeypatch.setattr(tui, "get_active_alerts", lambda: [])
    monkeypatch.setattr(
        "lattice.file_access.identity.load_node_identity",
        lambda: SimpleNamespace(node_id="worker-id"),
    )
    monkeypatch.setattr(
        "lattice.onboarding.get_worker_master_endpoint",
        lambda: {
            "hostname": "master-node",
            "ip": "10.77.0.200",
            "port": 9999,
        },
    )

    class FakeHealth:
        def current_snapshot(self):
            return {
                "status": "healthy",
                "fleet_generation": 29,
                "file_transport_generation": 29,
                "shell_transport_generation": 29,
                "services": [
                    {"name": "network", "status": "healthy"},
                    {"name": "fleet_sync", "status": "healthy"},
                    {"name": "mounts", "status": "healthy"},
                    {"name": "trusted_shell", "status": "healthy"},
                    {"name": "lattice_core", "status": "healthy"},
                    {"name": "backup", "status": "healthy"},
                ],
                "mount_observations": [
                    {"peer_node_id": "master-id", "state": "mounted"},
                    {"peer_node_id": "backup-node-id", "state": "mounted"},
                ],
            }

    monkeypatch.setattr("lattice.worker.health.HealthChecker", FakeHealth)
    monkeypatch.setattr(
        "lattice.backup.observations.local_backup_observations",
        lambda: [{
            "job_uuid": "job-uuid",
            "state": "healthy",
            "last_result": "successful",
            "last_success_at": "2026-09-05T01:00:00+00:00",
            "failure_streak": 0,
            "last_deep_verification_at": "2026-09-05T00:30:00+00:00",
        }],
    )
    monkeypatch.setattr(
        "lattice.backup.observations.local_backup_target_observations",
        lambda: [],
    )

    status = tui._worker_status()
    worker = status.health["worker"]

    assert status.role == "worker"
    assert status.master_hostname == "master-node"
    assert status.master_ip == "10.77.0.200"
    assert status.workers == []
    assert worker["hostname"] == "worker-node"
    assert worker["master_hostname"] == "master-node"
    assert worker["in_sync"] is True
    assert {row["hostname"] for row in worker["mounts"]} == {
        "master-node",
        "backup-node",
    }
    assert {row["hostname"] for row in worker["shell_connections"]} == {
        "master-node",
        "backup-node",
    }
    assert worker["backup_jobs"][0]["observation"]["state"] == "healthy"
    assert worker["hosted_targets"] == []


def test_worker_status_exposes_hosted_backup_storage_generically(tmp_path, monkeypatch):
    db = _worker_db(tmp_path)

    monkeypatch.setattr(tui, "get_db_connection", lambda: _open_db(db))
    monkeypatch.setattr(tui.socket, "gethostname", lambda: "worker-node")
    monkeypatch.setattr(tui, "_service_active", lambda _unit: "running")
    monkeypatch.setattr(tui, "get_active_alerts", lambda: [])
    monkeypatch.setattr(
        "lattice.file_access.identity.load_node_identity",
        lambda: SimpleNamespace(node_id="worker-id"),
    )
    monkeypatch.setattr(
        "lattice.onboarding.get_worker_master_endpoint",
        lambda: {"hostname": "master-node", "ip": "10.77.0.200", "port": 9999},
    )

    class FakeHealth:
        def current_snapshot(self):
            return {
                "status": "healthy",
                "fleet_generation": 2,
                "file_transport_generation": 2,
                "shell_transport_generation": 2,
                "services": [],
                "mount_observations": [],
            }

    monkeypatch.setattr("lattice.worker.health.HealthChecker", FakeHealth)
    monkeypatch.setattr(
        "lattice.backup.observations.local_backup_observations",
        lambda: [],
    )
    hosted = [{
        "target_uuid": "generic-target",
        "present": True,
        "health": "healthy",
        "mountpoint": "/mnt/backup",
        "total_bytes": 1000,
        "free_bytes": 700,
    }]
    monkeypatch.setattr(
        "lattice.backup.observations.local_backup_target_observations",
        lambda: hosted,
    )

    status = tui._worker_status()
    assert status.health["worker"]["hosted_targets"] == hosted


def test_get_status_never_falls_back_to_master_dashboard_for_worker(monkeypatch):
    monkeypatch.setattr("lattice.wizard.lifecycle.current_role", lambda: "worker")

    def explode():
        raise RuntimeError("worker status failed")

    monkeypatch.setattr(tui, "_worker_status", explode)
    with pytest.raises(RuntimeError, match="worker status failed"):
        tui.get_status()


def test_worker_refuses_fleet_wipe_below_ui(monkeypatch):
    monkeypatch.setattr("lattice.wizard.lifecycle.current_role", lambda: "worker")
    monkeypatch.setattr(
        wipe_cmd,
        "get_db_connection",
        lambda: (_ for _ in ()).throw(AssertionError("DB must not be touched")),
    )
    messages = []
    assert wipe_cmd.perform_wipe(output=messages.append) == 1
    assert any("only on the Lattice Master" in value for value in messages)


def test_worker_refuses_worker_removal_below_ui(monkeypatch):
    monkeypatch.setattr(workers_cmd, "current_role", lambda: "worker")
    monkeypatch.setattr(
        workers_cmd,
        "get_db_connection",
        lambda: (_ for _ in ()).throw(AssertionError("DB must not be touched")),
    )
    messages = []
    assert workers_cmd.remove_worker_safely(
        "backup-node",
        ask_confirmation=False,
        output=messages.append,
    ) == 1
    assert any("only on the Lattice Master" in value for value in messages)


def test_worker_refuses_master_side_pairing(monkeypatch):
    monkeypatch.setattr("lattice.wizard.lifecycle.current_role", lambda: "worker")
    with pytest.raises(PairingError, match="only on the Lattice Master"):
        pair_worker(
            hostname="new-worker",
            worker_ip="10.77.0.50",
            pairing_id="pairing-id",
            code="ABCDEFGH-ABCDEFG",
        )


def test_unknown_role_refuses_fleet_wipe(monkeypatch):
    monkeypatch.setattr(
        "lattice.wizard.lifecycle.current_role",
        lambda: None,
    )
    messages = []
    assert wipe_cmd.perform_wipe(output=messages.append) == 1
    assert any("only on the Lattice Master" in value for value in messages)


def test_worker_backup_flow_uses_restricted_backup_helper(monkeypatch):
    status = tui.LatticeStatus(
        role="worker",
        master_hostname="master-node",
        master_ip="10.77.0.200",
        daemon_status="running",
        uptime="1h",
        version="0.1.0",
        workers=[],
        alerts=[],
        health={"worker": {
            "backup_jobs": [{
                "job_uuid": "job-uuid",
                "enabled": 1,
                "paused": 0,
                "source_path": "/home/user",
                "friendly_name": "Backup Drive",
                "observation": {"state": "healthy", "failure_streak": 0},
            }],
            "hosted_targets": [],
        }},
    )
    choices = iter([0, 2])
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr(tui, "_flow_message", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tui, "_modal_getch", lambda *_args, **_kwargs: 0)
    calls = []
    monkeypatch.setattr(
        tui,
        "_backup_control",
        lambda *args: calls.append(args) or {"status": "accepted"},
    )

    tui._worker_backup_flow(object(), status, None)

    assert calls == [("run-now", "job-uuid")]


def test_worker_repair_uses_only_allowlisted_action_helper(monkeypatch):
    status = tui.LatticeStatus(
        role="worker",
        master_hostname="master-node",
        master_ip="10.77.0.200",
        daemon_status="running",
        uptime="1h",
        version="0.1.0",
        workers=[],
        alerts=[],
        health={"worker": {}},
    )
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(tui, "_flow_message", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(tui, "_modal_getch", lambda *_args, **_kwargs: 0)
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(tui.subprocess, "run", fake_run)

    tui._worker_repair_flow(object(), status, None)

    assert seen["command"] == [
        "/usr/bin/sudo",
        "-n",
        "/opt/lattice/bin/lattice-action-exec",
        "restart",
        "lattice-worker.service",
    ]
    assert seen["kwargs"]["timeout"] == 45


def test_worker_backup_browse_is_scoped_to_local_job(monkeypatch):
    status = tui.LatticeStatus(
        role="worker",
        master_hostname="master-node",
        master_ip="10.77.0.200",
        daemon_status="running",
        uptime="1h",
        version="0.1.0",
        workers=[],
        alerts=[],
        health={"worker": {
            "hostname": "worker-node",
            "backup_jobs": [{
                "job_uuid": "local-job",
                "enabled": 1,
                "paused": 0,
                "source_path": "/home/user",
                "friendly_name": "Backup Drive",
                "observation": {"state": "healthy", "failure_streak": 0},
            }],
            "hosted_targets": [],
        }},
    )
    choices = iter([1, 2])
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: next(choices))
    seen = []
    monkeypatch.setattr(
        tui,
        "_browse_backup_job_flow",
        lambda _screen, job: seen.append(dict(job)),
    )

    tui._worker_backup_flow(object(), status, None)

    assert seen == [{
        "job_uuid": "local-job",
        "source_hostname": "worker-node",
        "target_name": "Backup Drive",
    }]


def test_master_browse_flow_still_selects_fleet_job_then_delegates(monkeypatch):
    jobs = [{
        "job_uuid": "fleet-job",
        "source_hostname": "worker-node",
        "target_name": "Backup Drive",
    }]
    monkeypatch.setattr(
        "lattice.operator_interface.execute_operator_request",
        lambda request: {"data": jobs},
    )
    monkeypatch.setattr(tui, "_control_menu", lambda *_args, **_kwargs: 0)
    seen = []
    monkeypatch.setattr(
        tui,
        "_browse_backup_job_flow",
        lambda _screen, job: seen.append(dict(job)),
    )

    tui._browse_backups_flow(object())

    assert seen == jobs
