import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

import pytest

from lattice.core.config import FileAccessConfig, LatticeConfig
from lattice.core.migrations import run_migrations
from lattice.file_access import identity as identity_module
from lattice.file_access.identity import (
    NodeIdentityError,
    ensure_node_identity,
    load_node_identity,
)


def test_node_identity_is_created_once_and_persists(tmp_path):
    path = tmp_path / "node-identity.json"

    first = ensure_node_identity(
        "masteruser",
        path=path,
        main_uid=1000,
        main_gid=1000,
    )
    second = ensure_node_identity(
        "masteruser",
        path=path,
        main_uid=1000,
        main_gid=1000,
    )

    assert first == second
    assert uuid.UUID(first.node_id).version == 4
    assert first.main_user == "masteruser"
    assert first.main_uid == 1000
    assert first.main_gid == 1000
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_node_identity_refuses_different_main_user(tmp_path):
    path = tmp_path / "node-identity.json"

    ensure_node_identity(
        "masteruser",
        path=path,
        main_uid=1000,
        main_gid=1000,
    )

    with pytest.raises(NodeIdentityError, match="belongs to main user"):
        ensure_node_identity(
            "somebodyelse",
            path=path,
            main_uid=1001,
            main_gid=1001,
        )


def test_node_identity_refuses_world_readable_file(tmp_path):
    path = tmp_path / "node-identity.json"

    identity = ensure_node_identity(
        "masteruser",
        path=path,
        main_uid=1000,
        main_gid=1000,
    )

    os.chmod(path, 0o644)

    with pytest.raises(NodeIdentityError, match="permissions are too broad"):
        load_node_identity(path)

    os.chmod(path, 0o600)
    assert load_node_identity(path) == identity


def test_node_identity_refuses_malformed_data(tmp_path):
    path = tmp_path / "node-identity.json"
    path.write_text(json.dumps({"node_id": "not-a-uuid"}))
    os.chmod(path, 0o600)

    with pytest.raises(NodeIdentityError):
        load_node_identity(path)


def test_file_access_config_defaults():
    config = FileAccessConfig()

    assert config.enabled is True
    assert config.port == 22022
    assert config.probe_interval_seconds == 15
    assert config.persistent_alert_seconds == 300
    assert config.retry_initial_seconds == 2.0
    assert config.retry_max_seconds == 300
    assert config.key_rotation_days == 90
    assert config.lan_only is True


def test_lattice_config_contains_file_access_defaults():
    config = LatticeConfig()
    assert config.file_access.enabled is True
    assert config.file_access.port == 22022


def test_file_access_database_foundation_is_idempotent():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")

    run_migrations(conn)
    run_migrations(conn)

    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }

    assert {
        "fleet_nodes",
        "fleet_state",
        "shares",
        "mount_preferences",
        "mount_state",
        "mount_observations",
        "fleet_settings",
    }.issubset(tables)

    indexes = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
    }

    assert "idx_fleet_nodes_membership" in indexes
    assert "idx_shares_owner" in indexes
    assert "idx_mount_state_status" in indexes
    assert "idx_mount_observations_peer" in indexes

    conn.close()


def test_mount_desired_state_and_peer_state_constraints():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)

    conn.execute(
        """
        INSERT INTO fleet_nodes (
            node_id, hostname, role, main_user, main_uid, main_gid,
            membership_state
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "11111111-1111-4111-8111-111111111111",
            "backup-node",
            "worker",
            "backupuser",
            1000,
            1000,
            "active",
        ),
    )

    conn.execute(
        """
        INSERT INTO mount_preferences (peer_node_id, desired_state)
        VALUES (?, 'mounted')
        """,
        ("11111111-1111-4111-8111-111111111111",),
    )

    conn.execute(
        """
        INSERT INTO mount_state (peer_node_id, state)
        VALUES (?, 'mounted')
        """,
        ("11111111-1111-4111-8111-111111111111",),
    )

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            UPDATE mount_preferences
            SET desired_state = 'garbage'
            WHERE peer_node_id = ?
            """,
            ("11111111-1111-4111-8111-111111111111",),
        )

    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            UPDATE mount_state
            SET state = 'garbage'
            WHERE peer_node_id = ?
            """,
            ("11111111-1111-4111-8111-111111111111",),
        )

    conn.close()


def test_production_node_identity_is_group_readable_by_lattice(tmp_path, monkeypatch):
    path = tmp_path / "node-identity.json"
    calls = []

    class Group:
        gr_gid = 997

    monkeypatch.setattr(identity_module, "DEFAULT_NODE_IDENTITY_PATH", path)
    monkeypatch.setattr(identity_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identity_module.grp, "getgrnam", lambda name: Group())
    monkeypatch.setattr(identity_module.os, "chown", lambda target, uid, gid: calls.append(("chown", Path(target), uid, gid)))
    real_chmod = identity_module.os.chmod
    monkeypatch.setattr(identity_module.os, "chmod", lambda target, mode: (calls.append(("chmod", Path(target), mode)), real_chmod(target, mode))[1])

    ident = identity_module.NodeIdentity(
        node_id=str(uuid.uuid4()), main_user="masteruser", main_uid=1000, main_gid=1000,
        created_at="2026-08-28T22:00:00+00:00",
    )
    identity_module._atomic_write_identity(path, ident)

    assert ("chown", path, 0, 997) in calls
    assert ("chmod", path, 0o640) in calls
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
