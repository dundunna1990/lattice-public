from types import SimpleNamespace

import lattice.file_access.applied_state as applied
from lattice.file_access.transport import (
    DEFAULT_AUTHORIZED_KEYS,
    DEFAULT_RUNTIME_AUTHORIZED_KEYS,
    render_sshd_config,
)


def test_file_transport_config_detects_old_authorized_keys_path(tmp_path):
    identity = SimpleNamespace(main_user="workeruser")
    config = tmp_path / "sshd_config"
    current = render_sshd_config(main_user=identity.main_user)
    config.write_text(current, encoding="utf-8")
    assert applied.file_transport_config_is_current(identity, path=config)

    stale = current.replace(
        str(DEFAULT_RUNTIME_AUTHORIZED_KEYS),
        str(DEFAULT_AUTHORIZED_KEYS),
    )
    config.write_text(stale, encoding="utf-8")
    assert not applied.file_transport_config_is_current(identity, path=config)


def test_same_generation_stale_config_requeues(monkeypatch):
    identity = SimpleNamespace(node_id="node-1", main_user="workeruser")
    manifest = {"generation": 2}
    queued = []

    import lattice.file_access.identity as identity_mod
    import lattice.file_access.sync as sync_mod
    import lattice.file_access.transport_queue as queue_mod

    monkeypatch.setattr(identity_mod, "load_node_identity", lambda: identity)
    monkeypatch.setattr(sync_mod, "get_cached_signed_manifest", lambda: (manifest, "signature"))
    monkeypatch.setattr(applied, "applied_generation", lambda path, node_id: 2)
    monkeypatch.setattr(applied, "record_applied_generation_in_db", lambda *args: True)
    monkeypatch.setattr(applied, "file_transport_config_is_current", lambda identity: False)
    monkeypatch.setattr(queue_mod, "queue_transport_reconcile", lambda m, s: queued.append((m, s)) or True)

    assert applied.ensure_file_transport_current() is True
    assert queued == [(manifest, "signature")]


def test_same_generation_current_config_does_not_requeue(monkeypatch):
    identity = SimpleNamespace(node_id="node-1", main_user="workeruser")
    manifest = {"generation": 2}
    queued = []

    import lattice.file_access.identity as identity_mod
    import lattice.file_access.sync as sync_mod
    import lattice.file_access.transport_queue as queue_mod
    import lattice.file_access.home_export as home_export_mod

    monkeypatch.setattr(identity_mod, "load_node_identity", lambda: identity)
    monkeypatch.setattr(home_export_mod, "home_bind_is_current", lambda identity: True)
    monkeypatch.setattr(sync_mod, "get_cached_signed_manifest", lambda: (manifest, "signature"))
    monkeypatch.setattr(applied, "applied_generation", lambda path, node_id: 2)
    monkeypatch.setattr(applied, "record_applied_generation_in_db", lambda *args: True)
    monkeypatch.setattr(applied, "file_transport_config_is_current", lambda identity: True)
    monkeypatch.setattr(queue_mod, "queue_transport_reconcile", lambda m, s: queued.append((m, s)) or True)

    assert applied.ensure_file_transport_current() is False
    assert queued == []


def test_same_generation_missing_home_bind_requeues(monkeypatch):
    identity = SimpleNamespace(node_id="node-1", main_user="workeruser")
    manifest = {"generation": 2}
    queued = []

    import lattice.file_access.identity as identity_mod
    import lattice.file_access.sync as sync_mod
    import lattice.file_access.transport_queue as queue_mod
    import lattice.file_access.home_export as home_export_mod

    monkeypatch.setattr(identity_mod, "load_node_identity", lambda: identity)
    monkeypatch.setattr(sync_mod, "get_cached_signed_manifest", lambda: (manifest, "signature"))
    monkeypatch.setattr(applied, "applied_generation", lambda path, node_id: 2)
    monkeypatch.setattr(applied, "record_applied_generation_in_db", lambda *args: True)
    monkeypatch.setattr(applied, "file_transport_config_is_current", lambda identity: True)
    monkeypatch.setattr(home_export_mod, "home_bind_is_current", lambda identity: False)
    monkeypatch.setattr(queue_mod, "queue_transport_reconcile", lambda m, s: queued.append((m, s)) or True)

    assert applied.ensure_file_transport_current() is True
    assert queued == [(manifest, "signature")]
