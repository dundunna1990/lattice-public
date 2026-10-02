import pytest
from datetime import datetime, timezone
import json
import sqlite3
import uuid

from lattice.core.migrations import run_migrations
from lattice.file_access.activation import (
    FleetActivationError,
    commit_worker_activation,
    discard_unacknowledged_worker_activation,
    reconcile_pending_worker_activation,
    revoke_worker_membership,
    stage_worker_activation,
)
from lattice.file_access.bootstrap import (
    ensure_master_fleet_bootstrap,
)
from lattice.file_access.identity import NodeIdentity
from lattice.file_access.keys import (
    ensure_file_client_identity,
    ensure_file_host_identity,
)
from lattice.file_access.manifest import (
    verify_manifest,
)


def _prepare_master(tmp_path, monkeypatch):
    master_node_id = str(uuid.uuid4())

    monkeypatch.setenv(
        "LATTICE_FILE_SSH_DIR",
        str(tmp_path / "master-file-ssh"),
    )
    monkeypatch.setenv(
        "LATTICE_FLEET_SIGNING_DIR",
        str(tmp_path / "fleet-signing"),
    )
    monkeypatch.setenv(
        "LATTICE_NODE_IDENTITY_PATH",
        str(tmp_path / "master-node.json"),
    )

    from lattice.file_access import profile

    def fake_identity(main_user, *, path=None):
        return NodeIdentity(
            node_id=master_node_id,
            main_user=main_user,
            main_uid=1000,
            main_gid=1000,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
        )

    monkeypatch.setattr(
        profile,
        "ensure_node_identity",
        fake_identity,
    )

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)

    bootstrap = ensure_master_fleet_bootstrap(
        conn,
        hostname="master-node",
        ip="10.77.0.88",
        main_user="masteruser",
    )

    conn.commit()

    return conn, bootstrap


def _insert_pending_worker(conn, tmp_path):
    client = ensure_file_client_identity(
        tmp_path / "worker-client"
    )
    host = ensure_file_host_identity(
        tmp_path / "worker-host"
    )
    node_id = str(uuid.uuid4())

    conn.execute(
        """
        INSERT INTO workers (
            id,
            hostname,
            status,
            ssh_user,
            ip
        )
        VALUES (
            1,
            'worker-node',
            'healthy',
            'workeruser',
            '10.77.0.201'
        )
        """
    )

    conn.execute(
        """
        INSERT INTO fleet_nodes (
            node_id,
            worker_id,
            hostname,
            role,
            main_user,
            main_uid,
            main_gid,
            file_public_key,
            file_key_generation,
            file_host_public_key,
            file_host_key_fingerprint,
            last_known_ip,
            membership_state,
            membership_generation
        )
        VALUES (
            ?,
            1,
            'worker-node',
            'worker',
            'workeruser',
            1000,
            1000,
            ?,
            1,
            ?,
            ?,
            '10.77.0.201',
            'pending',
            0
        )
        """,
        (
            node_id,
            client.public_key_text,
            host.public_key_text,
            host.fingerprint,
        ),
    )

    conn.commit()
    return node_id


def test_pending_worker_gets_signed_next_generation(
    tmp_path,
    monkeypatch,
):
    conn, bootstrap = _prepare_master(
        tmp_path,
        monkeypatch,
    )

    worker_node_id = _insert_pending_worker(
        conn,
        tmp_path,
    )

    candidate = stage_worker_activation(
        conn,
        target_node_id=worker_node_id,
    )

    conn.commit()

    assert candidate.generation == 2

    member_ids = {
        member["node_id"]
        for member in candidate.manifest["members"]
    }

    assert bootstrap.node_id in member_ids
    assert worker_node_id in member_ids

    assert verify_manifest(
        candidate.manifest,
        candidate.signature,
        bootstrap.fleet_signing_public_key,
    )

    saved = conn.execute(
        """
        SELECT generation
        FROM fleet_pending_updates
        WHERE target_node_id = ?
        """,
        (worker_node_id,),
    ).fetchone()

    assert saved["generation"] == 2

    # Staging is idempotent while waiting for the ACK.
    same = stage_worker_activation(
        conn,
        target_node_id=worker_node_id,
    )

    assert same.generation == 2
    assert same.signature == candidate.signature

    conn.close()


def test_unacknowledged_activation_can_be_safely_discarded(
    tmp_path,
    monkeypatch,
):
    conn, _ = _prepare_master(tmp_path, monkeypatch)
    worker_node_id = _insert_pending_worker(conn, tmp_path)
    candidate = stage_worker_activation(conn, target_node_id=worker_node_id)

    assert discard_unacknowledged_worker_activation(
        conn,
        target_node_id=worker_node_id,
        generation=candidate.generation,
    ) is True
    conn.commit()

    assert conn.execute(
        "SELECT 1 FROM fleet_pending_updates WHERE target_node_id=?",
        (worker_node_id,),
    ).fetchone() is None
    state = conn.execute(
        "SELECT membership_state FROM fleet_nodes WHERE node_id=?",
        (worker_node_id,),
    ).fetchone()
    assert state["membership_state"] == "pending"
    assert conn.execute("SELECT generation FROM fleet_state WHERE id=1").fetchone()[0] == 1
    conn.close()


def test_activation_discard_refuses_after_master_generation_advances(
    tmp_path,
    monkeypatch,
):
    conn, _ = _prepare_master(tmp_path, monkeypatch)
    worker_node_id = _insert_pending_worker(conn, tmp_path)
    candidate = stage_worker_activation(conn, target_node_id=worker_node_id)
    conn.execute("UPDATE fleet_state SET generation=?", (candidate.generation,))
    with pytest.raises(
        FleetActivationError,
        match="fleet generation changed",
    ):
        discard_unacknowledged_worker_activation(
            conn,
            target_node_id=worker_node_id,
            generation=candidate.generation,
        )
    conn.rollback()
    conn.close()


def test_worker_becomes_active_only_after_commit(
    tmp_path,
    monkeypatch,
):
    conn, _ = _prepare_master(
        tmp_path,
        monkeypatch,
    )

    worker_node_id = _insert_pending_worker(
        conn,
        tmp_path,
    )

    candidate = stage_worker_activation(
        conn,
        target_node_id=worker_node_id,
    )

    before = conn.execute(
        """
        SELECT membership_state
        FROM fleet_nodes
        WHERE node_id = ?
        """,
        (worker_node_id,),
    ).fetchone()

    assert before["membership_state"] == "pending"

    commit_worker_activation(
        conn,
        target_node_id=worker_node_id,
        generation=candidate.generation,
    )

    conn.commit()

    worker = conn.execute(
        """
        SELECT
            membership_state,
            membership_generation
        FROM fleet_nodes
        WHERE node_id = ?
        """,
        (worker_node_id,),
    ).fetchone()

    assert tuple(worker) == ("active", 2)

    state = conn.execute(
        """
        SELECT generation, manifest
        FROM fleet_state
        WHERE id = 1
        """
    ).fetchone()

    assert state["generation"] == 2

    manifest = json.loads(state["manifest"])

    assert manifest["generation"] == 2

    assert conn.execute(
        """
        SELECT 1
        FROM fleet_pending_updates
        WHERE target_node_id = ?
        """,
        (worker_node_id,),
    ).fetchone() is None

    conn.close()


def test_revocation_immediately_publishes_signed_generation(tmp_path, monkeypatch):
    conn, bootstrap = _prepare_master(tmp_path, monkeypatch)
    worker_node_id = _insert_pending_worker(conn, tmp_path)
    activation = stage_worker_activation(conn, target_node_id=worker_node_id)
    commit_worker_activation(
        conn, target_node_id=worker_node_id, generation=activation.generation
    )
    conn.commit()

    revoked = revoke_worker_membership(conn, target_node_id=worker_node_id)
    conn.commit()

    assert revoked.generation == activation.generation + 1
    assert worker_node_id in revoked.manifest["revoked"]
    assert worker_node_id not in {m["node_id"] for m in revoked.manifest["members"]}
    assert bootstrap.node_id in {m["node_id"] for m in revoked.manifest["members"]}
    state = conn.execute("SELECT generation, manifest, signature, signing_public_key FROM fleet_state WHERE id=1").fetchone()
    assert state["generation"] == revoked.generation
    assert verify_manifest(json.loads(state["manifest"]), state["signature"], state["signing_public_key"])
    row = conn.execute("SELECT membership_state, membership_generation FROM fleet_nodes WHERE node_id=?", (worker_node_id,)).fetchone()
    assert row["membership_state"] == "revoked"
    assert row["membership_generation"] == revoked.generation


def test_reconcile_pending_activation_commits_worker_confirmed_generation(
    tmp_path,
    monkeypatch,
):
    conn, _ = _prepare_master(tmp_path, monkeypatch)
    worker_node_id = _insert_pending_worker(conn, tmp_path)
    candidate = stage_worker_activation(conn, target_node_id=worker_node_id)

    outcome = reconcile_pending_worker_activation(
        conn,
        target_node_id=worker_node_id,
        reported_generation=candidate.generation,
    )
    conn.commit()

    assert outcome == "committed"
    row = conn.execute(
        "SELECT membership_state,membership_generation FROM fleet_nodes WHERE node_id=?",
        (worker_node_id,),
    ).fetchone()
    assert tuple(row) == ("active", candidate.generation)
    assert conn.execute(
        "SELECT 1 FROM fleet_pending_updates WHERE target_node_id=?",
        (worker_node_id,),
    ).fetchone() is None
    conn.close()


def test_reconcile_pending_activation_discards_when_worker_is_still_behind(
    tmp_path,
    monkeypatch,
):
    conn, _ = _prepare_master(tmp_path, monkeypatch)
    worker_node_id = _insert_pending_worker(conn, tmp_path)
    candidate = stage_worker_activation(conn, target_node_id=worker_node_id)

    outcome = reconcile_pending_worker_activation(
        conn,
        target_node_id=worker_node_id,
        reported_generation=0,
    )
    conn.commit()

    assert outcome == "discarded"
    row = conn.execute(
        "SELECT membership_state,membership_generation FROM fleet_nodes WHERE node_id=?",
        (worker_node_id,),
    ).fetchone()
    assert row["membership_state"] == "pending"
    assert int(row["membership_generation"]) < candidate.generation
    assert conn.execute(
        "SELECT 1 FROM fleet_pending_updates WHERE target_node_id=?",
        (worker_node_id,),
    ).fetchone() is None
    conn.close()


def test_reconcile_pending_activation_preserves_contradictory_newer_worker_state(
    tmp_path,
    monkeypatch,
):
    conn, _ = _prepare_master(tmp_path, monkeypatch)
    worker_node_id = _insert_pending_worker(conn, tmp_path)
    candidate = stage_worker_activation(conn, target_node_id=worker_node_id)

    with pytest.raises(
        FleetActivationError,
        match="newer than the staged activation",
    ):
        reconcile_pending_worker_activation(
            conn,
            target_node_id=worker_node_id,
            reported_generation=candidate.generation + 1,
        )

    assert conn.execute(
        "SELECT generation FROM fleet_pending_updates WHERE target_node_id=?",
        (worker_node_id,),
    ).fetchone()["generation"] == candidate.generation
    conn.close()
