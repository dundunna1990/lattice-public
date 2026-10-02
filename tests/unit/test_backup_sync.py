from types import SimpleNamespace
import uuid

import pytest

from lattice.backup import sync
from lattice.backup.assignment import sign_assignment
from lattice.backup.keys import (
    ensure_backup_client_identity,
    ensure_backup_host_identity,
)
from lattice.file_access.keys import ensure_fleet_signing_identity


def _assignment(fleet_id, generation=1, assignments=None):
    return {
        "schema_version": 1,
        "fleet_id": fleet_id,
        "generation": generation,
        "assignments": assignments or [],
    }


def _setup(tmp_path, monkeypatch):
    fleet_id = str(uuid.uuid4())
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    cache = tmp_path / "backup-assignment.json"
    applied = tmp_path / "backup-applied.json"
    monkeypatch.setenv("LATTICE_BACKUP_ASSIGNMENT_CACHE", str(cache))
    monkeypatch.setattr(sync, "BACKUP_APPLIED_PATH", applied)
    monkeypatch.setattr(
        sync,
        "load_pinned_fleet_bootstrap",
        lambda: {
            "fleet_id": fleet_id,
            "fleet_signing_public_key": signer.public_key_text,
        },
    )
    node_id = str(uuid.uuid4())
    monkeypatch.setattr(
        sync,
        "load_node_identity",
        lambda: SimpleNamespace(node_id=node_id),
    )
    queued = []
    monkeypatch.setattr(
        sync,
        "queue_backup_transport_reconcile",
        lambda assignment, signature: queued.append((assignment, signature)) or True,
    )
    return fleet_id, signer, node_id, cache, applied, queued


def test_apply_signed_assignment_caches_and_queues(tmp_path, monkeypatch):
    fleet_id, signer, _, cache, _, queued = _setup(tmp_path, monkeypatch)
    assignment = _assignment(fleet_id)
    signature = sign_assignment(assignment, signer.private_key)
    result = sync.apply_signed_backup_assignment(assignment, signature)
    assert result == {"generation": 1, "status": "applied"}
    assert cache.exists()
    assert len(queued) == 1


def test_same_generation_is_current_but_requeues_until_root_applies(
    tmp_path,
    monkeypatch,
):
    fleet_id, signer, _, _, _, queued = _setup(tmp_path, monkeypatch)
    assignment = _assignment(fleet_id)
    signature = sign_assignment(assignment, signer.private_key)
    sync.apply_signed_backup_assignment(assignment, signature)
    queued.clear()
    result = sync.apply_signed_backup_assignment(assignment, signature)
    assert result == {"generation": 1, "status": "current"}
    assert len(queued) == 1


def test_rejects_assignment_rollback(tmp_path, monkeypatch):
    fleet_id, signer, _, _, _, _ = _setup(tmp_path, monkeypatch)
    newer = _assignment(fleet_id, generation=2)
    newer_sig = sign_assignment(newer, signer.private_key)
    sync.apply_signed_backup_assignment(newer, newer_sig)
    older = _assignment(fleet_id, generation=1)
    older_sig = sign_assignment(older, signer.private_key)
    with pytest.raises(sync.BackupSyncError, match="roll back"):
        sync.apply_signed_backup_assignment(older, older_sig)


def test_rejects_same_generation_conflict(tmp_path, monkeypatch):
    fleet_id, signer, _, _, _, _ = _setup(tmp_path, monkeypatch)
    first = _assignment(fleet_id)
    first_sig = sign_assignment(first, signer.private_key)
    sync.apply_signed_backup_assignment(first, first_sig)
    client = ensure_backup_client_identity(tmp_path / "other-client")
    host = ensure_backup_host_identity(tmp_path / "other-host")
    second = _assignment(
        fleet_id,
        assignments=[{
            "source_node_id": str(uuid.uuid4()),
            "target_node_id": str(uuid.uuid4()),
            "target_uuid": str(uuid.uuid4()),
            "repository_id": str(uuid.uuid4()),
            "backup_public_key": client.public_key_text,
            "backup_host_public_key": host.public_key_text,
            "backup_host_key_fingerprint": host.fingerprint,
        }],
    )
    second_sig = sign_assignment(second, signer.private_key)
    with pytest.raises(sync.BackupSyncError, match="Conflicting"):
        sync.apply_signed_backup_assignment(second, second_sig)


def test_applied_generation_does_not_requeue(tmp_path, monkeypatch):
    fleet_id, signer, _, _, _, queued = _setup(tmp_path, monkeypatch)
    assignment = _assignment(fleet_id)
    signature = sign_assignment(assignment, signer.private_key)
    monkeypatch.setattr(sync, "applied_generation", lambda *_args: 1)
    monkeypatch.setattr(sync, "_backup_transport_health", lambda *_args: "current")
    sync.apply_signed_backup_assignment(assignment, signature)
    assert queued == []


def test_applied_generation_requeues_repairable_transport(tmp_path, monkeypatch):
    fleet_id, signer, _, _, _, queued = _setup(tmp_path, monkeypatch)
    assignment = _assignment(fleet_id)
    signature = sign_assignment(assignment, signer.private_key)
    monkeypatch.setattr(sync, "applied_generation", lambda *_args: 1)
    monkeypatch.setattr(sync, "_backup_transport_health", lambda *_args: "repairable")
    sync.apply_signed_backup_assignment(assignment, signature)
    assert len(queued) == 1


def test_applied_generation_refuses_unsafe_transport(tmp_path, monkeypatch):
    fleet_id, signer, _, _, _, queued = _setup(tmp_path, monkeypatch)
    assignment = _assignment(fleet_id)
    signature = sign_assignment(assignment, signer.private_key)
    monkeypatch.setattr(sync, "applied_generation", lambda *_args: 1)
    monkeypatch.setattr(sync, "_backup_transport_health", lambda *_args: "unsafe")
    with pytest.raises(sync.BackupSyncError, match="unsafe"):
        sync.apply_signed_backup_assignment(assignment, signature)
    assert queued == []


def test_backup_transport_health_marks_missing_bind_repairable(tmp_path, monkeypatch):
    node_id = str(uuid.uuid4())
    source_id = str(uuid.uuid4())
    target_uuid = str(uuid.uuid4())
    source = tmp_path / "drive" / "LatticeBackups" / source_id
    source.mkdir(parents=True)
    item = SimpleNamespace(repository_path=source, username="lattice-bkp-test")
    assignment = _assignment(
        str(uuid.uuid4()),
        assignments=[{
            "target_node_id": node_id,
            "source_node_id": source_id,
            "target_uuid": target_uuid,
        }],
    )
    monkeypatch.setattr(
        sync,
        "load_pinned_fleet_bootstrap",
        lambda: {"fleet_signing_public_key": "ignored"},
    )
    monkeypatch.setattr(
        sync,
        "ensure_backup_host_identity",
        lambda: SimpleNamespace(public_key_text="ignored"),
    )
    monkeypatch.setattr(sync, "build_local_transport_plan", lambda *a, **k: [item])
    monkeypatch.setattr(sync, "exact_mount_source", lambda _target: None)
    assert sync._backup_transport_health(
        assignment, "signature", SimpleNamespace(node_id=node_id)
    ) == "repairable"


def test_backup_transport_health_accepts_master_signing_key(tmp_path, monkeypatch):
    node_id = str(uuid.uuid4())
    source_id = str(uuid.uuid4())
    source = tmp_path / "drive" / "LatticeBackups" / source_id
    source.mkdir(parents=True)
    item = SimpleNamespace(repository_path=source, username="lattice-bkp-test")
    assignment = _assignment(
        str(uuid.uuid4()),
        assignments=[{"target_node_id": node_id, "source_node_id": source_id}],
    )
    monkeypatch.setattr(
        sync,
        "load_pinned_fleet_bootstrap",
        lambda: (_ for _ in ()).throw(AssertionError("worker bootstrap must not be used")),
    )
    monkeypatch.setattr(
        sync,
        "ensure_backup_host_identity",
        lambda: SimpleNamespace(public_key_text="host-public"),
    )
    seen = {}

    def build_plan(_assignment, _signature, signing_public_key, **_kwargs):
        seen["signing_public_key"] = signing_public_key
        return [item]

    monkeypatch.setattr(sync, "build_local_transport_plan", build_plan)
    monkeypatch.setattr(sync, "exact_mount_source", lambda _target: None)

    assert sync._backup_transport_health(
        assignment,
        "signature",
        SimpleNamespace(node_id=node_id),
        signing_public_key="master-public",
    ) == "repairable"
    assert seen["signing_public_key"] == "master-public"


def test_backup_transport_health_refuses_missing_repository(tmp_path, monkeypatch):
    node_id = str(uuid.uuid4())
    source_id = str(uuid.uuid4())
    item = SimpleNamespace(
        repository_path=tmp_path / "missing-repository",
        username="lattice-bkp-test",
    )
    assignment = _assignment(
        str(uuid.uuid4()),
        assignments=[{"target_node_id": node_id, "source_node_id": source_id}],
    )
    monkeypatch.setattr(
        sync,
        "load_pinned_fleet_bootstrap",
        lambda: {"fleet_signing_public_key": "ignored"},
    )
    monkeypatch.setattr(
        sync,
        "ensure_backup_host_identity",
        lambda: SimpleNamespace(public_key_text="ignored"),
    )
    monkeypatch.setattr(sync, "build_local_transport_plan", lambda *a, **k: [item])
    assert sync._backup_transport_health(
        assignment, "signature", SimpleNamespace(node_id=node_id)
    ) == "unsafe"
