import json
import sqlite3
from types import SimpleNamespace
import uuid

import pytest

from lattice.backup import assignment_state
from lattice.backup.assignment import verify_assignment
from lattice.backup.sync import BackupSyncError
from lattice.backup.assignment_state import (
    BackupAssignmentStateError,
    reconcile_assignment_state,
)
from lattice.backup.keys import (
    ensure_backup_client_identity,
    ensure_backup_host_identity,
)
from lattice.core.migrations import run_migrations
from lattice.file_access.keys import ensure_fleet_signing_identity


def _setup(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "lattice.backup.assignment_state.ensure_local_backup_identity_record",
        lambda: False,
    )
    monkeypatch.setattr(
        "lattice.backup.assignment_state._ensure_local_transport",
        lambda _state: None,
    )
    db = tmp_path / "state.sqlite"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db))
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    run_migrations(conn)
    source = str(uuid.uuid4())
    target = str(uuid.uuid4())
    target_uuid = str(uuid.uuid4())
    job_uuid = str(uuid.uuid4())
    client = ensure_backup_client_identity(tmp_path / "source-key")
    host = ensure_backup_host_identity(tmp_path / "target-key")
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    fleet_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO fleet_state(id,fleet_id,generation,manifest,signature,signing_public_key) VALUES(1,?,1,'{}','sig',?)",
        (fleet_id, signer.public_key_text),
    )
    for node_id, hostname, backup_client, backup_host in (
        (source, "worker-node", client.public_key_text, None),
        (target, "backup-node", None, host.public_key_text),
    ):
        conn.execute(
            """INSERT INTO fleet_nodes(
                   node_id,hostname,role,main_user,main_uid,main_gid,membership_state,
                   backup_public_key,backup_key_generation,
                   backup_host_public_key,backup_host_key_fingerprint)
               VALUES(?,?,?,?,?,?, 'active', ?,1,?,?)""",
            (
                node_id, hostname, "worker", "user", 1000, 1000,
                backup_client, backup_host,
                host.fingerprint if backup_host else None,
            ),
        )
    cursor = conn.execute(
        """INSERT INTO backup_targets(
               target_uuid,friendly_name,host_node_id,target_type,
               filesystem_uuid,repository_root)
           VALUES(?,?,?,?,?,?)""",
        (
            target_uuid, "Backup Drive", target,
            "remote_storage", "disk-uuid", "/mnt/backup/LatticeBackups",
        ),
    )
    conn.execute(
        """INSERT INTO backup_jobs(
               job_uuid,source_node_id,target_id,source_path)
           VALUES(?,?,?,?)""",
        (job_uuid, source, cursor.lastrowid, "/home/user"),
    )
    conn.commit()
    conn.close()
    return {
        "source": source,
        "target": target,
        "target_uuid": target_uuid,
        "job_uuid": job_uuid,
        "signer": signer,
        "db": db,
    }


def test_assignment_state_is_signed_and_stable(tmp_path, monkeypatch):
    state = _setup(tmp_path, monkeypatch)
    first = reconcile_assignment_state(
        signing_private_key=state["signer"].private_key,
    )
    second = reconcile_assignment_state(
        signing_private_key=state["signer"].private_key,
    )
    assert first == second
    assert first["assignment"]["generation"] == 1
    item = first["assignment"]["assignments"][0]
    assert item["source_node_id"] == state["source"]
    assert item["target_node_id"] == state["target"]
    assert item["target_uuid"] == state["target_uuid"]
    assert item["repository_id"] == state["job_uuid"]
    assert verify_assignment(
        first["assignment"],
        first["signature"],
        state["signer"].public_key_text,
    )


def test_assignment_generation_changes_when_job_is_paused(tmp_path, monkeypatch):
    state = _setup(tmp_path, monkeypatch)
    first = reconcile_assignment_state(
        signing_private_key=state["signer"].private_key,
    )
    conn = sqlite3.connect(state["db"])
    conn.execute("UPDATE backup_jobs SET paused=1, pause_reason='Maintenance'")
    conn.commit(); conn.close()
    second = reconcile_assignment_state(
        signing_private_key=state["signer"].private_key,
    )
    assert second["assignment"]["generation"] == first["assignment"]["generation"] + 1
    assert second["assignment"]["assignments"] == []


def test_assignment_state_requires_enrolled_source_identity(tmp_path, monkeypatch):
    state = _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(state["db"])
    conn.execute(
        "UPDATE fleet_nodes SET backup_public_key=NULL, backup_key_generation=0 WHERE node_id=?",
        (state["source"],),
    )
    conn.commit(); conn.close()
    with pytest.raises(BackupAssignmentStateError, match="has not enrolled"):
        reconcile_assignment_state(
            signing_private_key=state["signer"].private_key,
        )


def test_master_local_transport_rechecks_current_generation(tmp_path, monkeypatch):
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    node_id = str(uuid.uuid4())
    monkeypatch.setattr(
        assignment_state,
        "DEFAULT_FLEET_SIGNING_DIR",
        tmp_path / "signing",
    )
    monkeypatch.setattr(
        assignment_state,
        "load_node_identity",
        lambda: SimpleNamespace(node_id=node_id),
    )
    calls = []
    monkeypatch.setattr(
        assignment_state,
        "ensure_backup_transport_current",
        lambda **kwargs: calls.append(kwargs) or False,
    )
    state = {"assignment": {"generation": 7}, "signature": "signed-state"}

    assignment_state._ensure_local_transport(state)

    assert calls == [{
        "assignment": state["assignment"],
        "signature": "signed-state",
        "signing_public_key": signer.public_key_text,
    }]


def test_master_local_transport_propagates_unsafe_refusal(tmp_path, monkeypatch):
    ensure_fleet_signing_identity(tmp_path / "signing")
    monkeypatch.setattr(
        assignment_state,
        "DEFAULT_FLEET_SIGNING_DIR",
        tmp_path / "signing",
    )
    monkeypatch.setattr(
        assignment_state,
        "load_node_identity",
        lambda: SimpleNamespace(node_id=str(uuid.uuid4())),
    )

    def refuse(**_kwargs):
        raise BackupSyncError("Backup transport state is unsafe")

    monkeypatch.setattr(
        assignment_state,
        "ensure_backup_transport_current",
        refuse,
    )

    with pytest.raises(BackupAssignmentStateError, match="unsafe"):
        assignment_state._ensure_local_transport(
            {"assignment": {"generation": 7}, "signature": "signed-state"}
        )
