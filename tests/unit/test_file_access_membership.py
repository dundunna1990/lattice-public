import base64
import sqlite3
import uuid

import pytest

from lattice.core.migrations import run_migrations
from lattice.file_access.keys import (
    fingerprint_ed25519_public_key,
)
from lattice.file_access.membership import (
    FleetIdentityError,
    record_worker_file_identity,
    validate_worker_file_offer,
)


def _key(fill: bytes, comment: str) -> str:
    wire = (
        b"\x00\x00\x00\x0bssh-ed25519"
        + b"\x00\x00\x00\x20"
        + fill * 32
    )
    return (
        "ssh-ed25519 "
        + base64.b64encode(wire).decode("ascii")
        + f" {comment}"
    )


def _offer():
    host_key = _key(b"h", "file-host")

    return {
        "hostname": "backup-node",
        "node_id": str(uuid.uuid4()),
        "main_user": "backupuser",
        "main_uid": 1000,
        "main_gid": 1000,
        "file_public_key": _key(b"f", "file-client"),
        "file_host_public_key": host_key,
        "file_host_key_fingerprint":
            fingerprint_ed25519_public_key(host_key),
        "file_key_generation": 1,
    }


def test_worker_file_offer_is_validated():
    identity = validate_worker_file_offer(
        _offer(),
        expected_hostname="backup-node",
    )

    assert identity.main_user == "backupuser"
    assert identity.file_key_generation == 1
    assert identity.file_host_key_fingerprint.startswith("SHA256:")


def test_worker_file_offer_rejects_wrong_host_fingerprint():
    offer = _offer()
    offer["file_host_key_fingerprint"] = "SHA256:wrong"

    with pytest.raises(FleetIdentityError, match="does not match"):
        validate_worker_file_offer(
            offer,
            expected_hostname="backup-node",
        )


def test_worker_file_offer_rejects_non_uuid4_node():
    offer = _offer()
    offer["node_id"] = str(uuid.uuid1())

    with pytest.raises(FleetIdentityError, match="UUIDv4"):
        validate_worker_file_offer(
            offer,
            expected_hostname="backup-node",
        )


def test_verified_worker_identity_is_persisted_pending():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)

    conn.execute(
        """
        INSERT INTO workers (
            id, hostname, status, ssh_user, ip
        )
        VALUES (
            1, 'backup-node', 'healthy',
            'backupuser', '10.77.0.85'
        )
        """
    )

    identity = validate_worker_file_offer(
        _offer(),
        expected_hostname="backup-node",
    )

    record_worker_file_identity(
        conn,
        worker_id=1,
        hostname="backup-node",
        ip="10.77.0.85",
        identity=identity,
    )

    row = conn.execute(
        """
        SELECT
            node_id,
            worker_id,
            hostname,
            main_user,
            file_host_key_fingerprint,
            membership_state
        FROM fleet_nodes
        """
    ).fetchone()

    assert row == (
        identity.node_id,
        1,
        "backup-node",
        "backupuser",
        identity.file_host_key_fingerprint,
        "pending",
    )

    conn.close()


def test_repair_to_new_node_keeps_old_identity_as_tombstone():
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys=ON")
    run_migrations(conn)

    conn.execute(
        """
        INSERT INTO workers (
            id, hostname, status, ssh_user, ip
        )
        VALUES (
            1, 'backup-node', 'healthy',
            'backupuser', '10.77.0.85'
        )
        """
    )

    first = validate_worker_file_offer(
        _offer(),
        expected_hostname="backup-node",
    )

    second_offer = _offer()
    second = validate_worker_file_offer(
        second_offer,
        expected_hostname="backup-node",
    )

    record_worker_file_identity(
        conn,
        worker_id=1,
        hostname="backup-node",
        ip="10.77.0.85",
        identity=first,
    )

    record_worker_file_identity(
        conn,
        worker_id=1,
        hostname="backup-node",
        ip="10.77.0.85",
        identity=second,
    )

    rows = conn.execute(
        """
        SELECT node_id, membership_state
        FROM fleet_nodes
        ORDER BY created_at, node_id
        """
    ).fetchall()

    states = {node_id: state for node_id, state in rows}

    assert states[first.node_id] == "revoked"
    assert states[second.node_id] == "pending"

    conn.close()
