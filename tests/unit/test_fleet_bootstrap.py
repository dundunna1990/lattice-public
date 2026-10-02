from datetime import datetime, timezone
import json
import sqlite3
import uuid

import pytest

from lattice.core.migrations import run_migrations
from lattice.file_access.bootstrap import (
    FleetBootstrapError,
    ensure_master_fleet_bootstrap,
    validate_master_bootstrap,
)
from lattice.file_access.identity import NodeIdentity
from lattice.file_access.keys import (
    ensure_file_client_identity,
    ensure_file_host_identity,
    ensure_fleet_signing_identity,
)
from lattice.file_access.manifest import verify_manifest


@pytest.fixture
def bootstrap_env(tmp_path, monkeypatch):
    node_id = str(uuid.uuid4())

    monkeypatch.setenv(
        "LATTICE_FILE_SSH_DIR",
        str(tmp_path / "file-ssh"),
    )
    monkeypatch.setenv(
        "LATTICE_FLEET_SIGNING_DIR",
        str(tmp_path / "fleet-signing"),
    )
    monkeypatch.setenv(
        "LATTICE_NODE_IDENTITY_PATH",
        str(tmp_path / "node-identity.json"),
    )

    from lattice.file_access import profile

    def fake_node_identity(main_user, *, path=None):
        return NodeIdentity(
            node_id=node_id,
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
        fake_node_identity,
    )

    return tmp_path, node_id


def test_master_bootstrap_creates_signed_generation_one(
    bootstrap_env,
):
    _, node_id = bootstrap_env

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)

    bootstrap = ensure_master_fleet_bootstrap(
        conn,
        hostname="master-node",
        ip="10.77.0.88",
        main_user="masteruser",
    )

    assert bootstrap.generation == 1
    assert bootstrap.node_id == node_id
    assert bootstrap.manifest["generation"] == 1
    assert len(bootstrap.manifest["members"]) == 1
    assert bootstrap.manifest["members"][0]["role"] == "master"

    assert verify_manifest(
        bootstrap.manifest,
        bootstrap.signature,
        bootstrap.fleet_signing_public_key,
    )

    row = conn.execute(
        """
        SELECT
            role,
            membership_state,
            membership_generation
        FROM fleet_nodes
        WHERE node_id = ?
        """,
        (node_id,),
    ).fetchone()

    assert row == ("master", "active", 1)

    state = conn.execute(
        """
        SELECT fleet_id, generation, manifest
        FROM fleet_state
        WHERE id = 1
        """
    ).fetchone()

    assert state[0] == bootstrap.fleet_id
    assert state[1] == 1
    assert json.loads(state[2]) == bootstrap.manifest

    conn.close()


def test_master_bootstrap_is_idempotent(
    bootstrap_env,
):
    _, node_id = bootstrap_env

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)

    first = ensure_master_fleet_bootstrap(
        conn,
        hostname="master-node",
        ip="10.77.0.88",
        main_user="masteruser",
    )

    second = ensure_master_fleet_bootstrap(
        conn,
        hostname="master-node",
        ip="10.77.0.88",
        main_user="masteruser",
    )

    assert second.fleet_id == first.fleet_id
    assert second.node_id == node_id
    assert second.generation == 1
    assert second.signature == first.signature

    count = conn.execute(
        "SELECT COUNT(*) FROM fleet_nodes"
    ).fetchone()[0]

    assert count == 1
    conn.close()


def test_master_bootstrap_validation_rejects_mismatched_host_key(
    tmp_path,
):
    client = ensure_file_client_identity(
        tmp_path / "client"
    )
    host = ensure_file_host_identity(
        tmp_path / "host"
    )
    signing = ensure_fleet_signing_identity(
        tmp_path / "signing"
    )

    with pytest.raises(
        FleetBootstrapError,
        match="fingerprint does not match",
    ):
        validate_master_bootstrap(
            fleet_id=str(uuid.uuid4()),
            master_node_id=str(uuid.uuid4()),
            master_file_public_key=
                client.public_key_text,
            master_file_host_public_key=
                host.public_key_text,
            master_file_host_key_fingerprint=
                "SHA256:not-the-key",
            fleet_signing_public_key=
                signing.public_key_text,
        )


def test_master_bootstrap_validation_accepts_real_keys(
    tmp_path,
):
    client = ensure_file_client_identity(
        tmp_path / "client"
    )
    host = ensure_file_host_identity(
        tmp_path / "host"
    )
    signing = ensure_fleet_signing_identity(
        tmp_path / "signing"
    )

    result = validate_master_bootstrap(
        fleet_id=str(uuid.uuid4()),
        master_node_id=str(uuid.uuid4()),
        master_file_public_key=
            client.public_key_text,
        master_file_host_public_key=
            host.public_key_text,
        master_file_host_key_fingerprint=
            host.fingerprint,
        fleet_signing_public_key=
            signing.public_key_text,
    )

    assert result[
        "master_file_host_key_fingerprint"
    ] == host.fingerprint
