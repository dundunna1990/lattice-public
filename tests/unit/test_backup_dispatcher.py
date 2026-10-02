from types import SimpleNamespace

import pytest

from lattice.backup import dispatcher
from lattice.backup.runner import BackupExecutionError


def test_dispatcher_runs_local_and_remote_due_jobs(monkeypatch):
    node_id = "11111111-1111-4111-8111-111111111111"
    monkeypatch.setattr(dispatcher, "load_node_identity", lambda: SimpleNamespace(node_id=node_id))
    monkeypatch.setattr(
        dispatcher,
        "due_jobs",
        lambda **kwargs: [
            {
                "id": 1,
                "source_hostname": "master-node",
                "target_name": "Local Backup",
                "target_type": "local_storage",
                "host_node_id": node_id,
            },
            {
                "id": 2,
                "source_hostname": "master-node",
                "target_name": "Backup Drive",
                "target_type": "remote_storage",
                "host_node_id": "22222222-2222-4222-8222-222222222222",
            },
        ],
    )
    local_called = []
    remote_called = []
    monkeypatch.setattr(
        dispatcher,
        "run_local_job",
        lambda job_id, **kwargs: local_called.append(job_id),
    )
    monkeypatch.setattr(
        dispatcher,
        "run_remote_job",
        lambda job_id, **kwargs: remote_called.append(job_id),
    )
    assert dispatcher.dispatch_due_jobs() == (2, 2, 0)
    assert local_called == [1]
    assert remote_called == [2]


def test_dispatcher_counts_local_failures(monkeypatch):
    node_id = "11111111-1111-4111-8111-111111111111"
    monkeypatch.setattr(dispatcher, "load_node_identity", lambda: SimpleNamespace(node_id=node_id))
    monkeypatch.setattr(
        dispatcher,
        "due_jobs",
        lambda **kwargs: [{
            "id": 1,
            "source_hostname": "master-node",
            "target_name": "Local Backup",
            "target_type": "local_storage",
            "host_node_id": node_id,
        }],
    )
    def fail(*args, **kwargs):
        raise BackupExecutionError("target missing")
    monkeypatch.setattr(dispatcher, "run_local_job", fail)
    assert dispatcher.dispatch_due_jobs() == (1, 0, 1)


def test_dispatcher_requires_local_identity(monkeypatch):
    monkeypatch.setattr(dispatcher, "load_node_identity", lambda: None)
    with pytest.raises(BackupExecutionError, match="identity"):
        dispatcher.dispatch_due_jobs()
