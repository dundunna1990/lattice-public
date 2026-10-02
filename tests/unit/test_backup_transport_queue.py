import uuid

import pytest

from lattice.backup.keys import (
    ensure_backup_client_identity,
    ensure_backup_host_identity,
)
from lattice.backup.assignment import sign_assignment
from lattice.backup.transport_queue import (
    BackupTransportQueueError,
    queue_backup_transport_reconcile,
)
from lattice.file_access.keys import ensure_fleet_signing_identity


def _payload(tmp_path, generation=1):
    client = ensure_backup_client_identity(tmp_path / "client")
    host = ensure_backup_host_identity(tmp_path / "host")
    return {
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": generation,
        "assignments": [{
            "source_node_id": str(uuid.uuid4()),
            "target_node_id": str(uuid.uuid4()),
            "target_uuid": str(uuid.uuid4()),
            "repository_id": str(uuid.uuid4()),
            "backup_public_key": client.public_key_text,
            "backup_host_public_key": host.public_key_text,
            "backup_host_key_fingerprint": host.fingerprint,
        }],
    }


def test_queue_writes_once_and_deduplicates(tmp_path, monkeypatch):
    path = tmp_path / "request.json"
    monkeypatch.setenv("LATTICE_BACKUP_TRANSPORT_REQUEST_PATH", str(path))
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    payload = _payload(tmp_path)
    signature = sign_assignment(payload, signer.private_key)
    assert queue_backup_transport_reconcile(payload, signature) is True
    assert queue_backup_transport_reconcile(payload, signature) is False
    assert path.stat().st_mode & 0o777 == 0o600


def test_queue_rejects_same_generation_conflict(tmp_path, monkeypatch):
    path = tmp_path / "request.json"
    monkeypatch.setenv("LATTICE_BACKUP_TRANSPORT_REQUEST_PATH", str(path))
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    first = _payload(tmp_path / "first")
    second = _payload(tmp_path / "second")
    second["fleet_id"] = first["fleet_id"]
    signature1 = sign_assignment(first, signer.private_key)
    signature2 = sign_assignment(second, signer.private_key)
    assert queue_backup_transport_reconcile(first, signature1)
    with pytest.raises(BackupTransportQueueError, match="Conflicting"):
        queue_backup_transport_reconcile(second, signature2)


def test_queue_does_not_replace_newer_pending_generation(tmp_path, monkeypatch):
    path = tmp_path / "request.json"
    monkeypatch.setenv("LATTICE_BACKUP_TRANSPORT_REQUEST_PATH", str(path))
    signer = ensure_fleet_signing_identity(tmp_path / "signing")
    newer = _payload(tmp_path / "newer", generation=2)
    older = dict(newer)
    older["generation"] = 1
    newer_sig = sign_assignment(newer, signer.private_key)
    older_sig = sign_assignment(older, signer.private_key)
    assert queue_backup_transport_reconcile(newer, newer_sig)
    assert queue_backup_transport_reconcile(older, older_sig) is False
