import json
import sqlite3
import uuid
from types import SimpleNamespace

from lattice.core.migrations import run_migrations
from lattice.file_access.keys import (
    _ensure_keypair,
    ensure_file_client_identity,
    ensure_file_host_identity,
    ensure_fleet_signing_identity,
)
from lattice.file_access.manifest import normalize_manifest, sign_manifest, verify_manifest
from lattice.shell_access.keys import ensure_shell_client_identity, ensure_shell_host_identity
from lattice.file_access import rotation


def _member(node_id, hostname, role, user, file_client, file_host, shell_client, shell_host):
    return {
        "node_id": node_id,
        "hostname": hostname,
        "role": role,
        "main_user": user,
        "file_public_key": file_client.public_key_text,
        "file_host_public_key": file_host.public_key_text,
        "file_host_key_fingerprint": file_host.fingerprint,
        "file_key_generation": 1,
        "shell_public_key": shell_client.public_key_text,
        "shell_host_public_key": shell_host.public_key_text,
        "shell_host_key_fingerprint": shell_host.fingerprint,
        "shell_key_generation": 1,
    }


def _setup_master_db(tmp_path, monkeypatch):
    db_path = tmp_path / "lattice.db"
    monkeypatch.setenv("LATTICE_DB_PATH", str(db_path))
    monkeypatch.setenv("LATTICE_FLEET_SIGNING_DIR", str(tmp_path / "signing"))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    run_migrations(conn)

    master_node = str(uuid.uuid4())
    worker_node = str(uuid.uuid4())
    master_file_client = ensure_file_client_identity(tmp_path / "master-file-client")
    master_file_host = ensure_file_host_identity(tmp_path / "master-file-host")
    master_shell_client = ensure_shell_client_identity(tmp_path / "master-shell")
    master_shell_host = ensure_shell_host_identity(tmp_path / "master-shell")
    worker_file_client = ensure_file_client_identity(tmp_path / "worker-file-client")
    worker_file_host = ensure_file_host_identity(tmp_path / "worker-file-host")
    worker_shell_client = ensure_shell_client_identity(tmp_path / "worker-shell")
    worker_shell_host = ensure_shell_host_identity(tmp_path / "worker-shell")
    signing = ensure_fleet_signing_identity(tmp_path / "signing")
    fleet_id = str(uuid.uuid4())
    manifest = normalize_manifest({
        "schema_version": 1,
        "fleet_id": fleet_id,
        "generation": 5,
        "members": [
            _member(master_node, "master-node", "master", "masteruser", master_file_client, master_file_host, master_shell_client, master_shell_host),
            _member(worker_node, "worker-node", "worker", "masteruser", worker_file_client, worker_file_host, worker_shell_client, worker_shell_host),
        ],
        "revoked": [],
    })
    signature = sign_manifest(manifest, signing.private_key)
    conn.execute(
        "INSERT INTO workers (id, hostname, status, ip, ssh_user) VALUES (1, 'worker-node', 'healthy', '10.77.0.20', 'masteruser')"
    )
    for node_id, worker_id, hostname, role, member in (
        (master_node, None, "master-node", "master", manifest["members"][0]),
        (worker_node, 1, "worker-node", "worker", manifest["members"][1]),
    ):
        conn.execute(
            """INSERT INTO fleet_nodes (
                   node_id, worker_id, hostname, role, main_user, main_uid, main_gid,
                   file_public_key, file_key_generation, file_host_public_key,
                   file_host_key_fingerprint, shell_public_key, shell_key_generation,
                   shell_host_public_key, shell_host_key_fingerprint, membership_state,
                   membership_generation
               ) VALUES (?, ?, ?, ?, 'masteruser', 1000, 1000, ?, 1, ?, ?, ?, 1, ?, ?, 'active', 5)""",
            (
                node_id, worker_id, hostname, role,
                member["file_public_key"], member["file_host_public_key"],
                member["file_host_key_fingerprint"], member["shell_public_key"],
                member["shell_host_public_key"], member["shell_host_key_fingerprint"],
            ),
        )
    conn.execute(
        "INSERT INTO fleet_state (id, fleet_id, generation, manifest, signature, signing_public_key) VALUES (1, ?, 5, ?, ?, ?)",
        (fleet_id, json.dumps(manifest, sort_keys=True, separators=(",", ":")), signature, signing.public_key_text),
    )
    conn.commit()
    conn.close()
    return {
        "master_node": master_node,
        "worker_node": worker_node,
        "worker_shell_client": worker_shell_client,
        "worker_shell_host": worker_shell_host,
        "signing": signing,
    }


def test_signed_file_rotation_waits_for_all_peers_then_finalizes(tmp_path, monkeypatch):
    setup = _setup_master_db(tmp_path, monkeypatch)
    next_client = _ensure_keypair(tmp_path / "proposal", "next_client_ed25519", "next-client")
    next_host = _ensure_keypair(tmp_path / "proposal", "next_host_ed25519", "next-host")
    proposal = {
        "node_id": setup["worker_node"],
        "current_generation": 1,
        "next_generation": 2,
        "next_public_key": next_client.public_key_text,
        "next_host_public_key": next_host.public_key_text,
        "next_host_key_fingerprint": next_host.fingerprint,
    }

    staged = rotation.process_master_rotation_proposal(setup["worker_node"], proposal)
    assert staged == {"status": "overlap", "generation": 6}

    conn = sqlite3.connect(tmp_path / "lattice.db")
    conn.row_factory = sqlite3.Row
    state = conn.execute("SELECT * FROM fleet_state WHERE id=1").fetchone()
    overlap = normalize_manifest(json.loads(state["manifest"]))
    assert state["generation"] == 6
    member = next(m for m in overlap["members"] if m["node_id"] == setup["worker_node"])
    assert member["file_next_public_key"] == next_client.public_key_text
    assert member["file_next_key_generation"] == 2
    assert verify_manifest(overlap, state["signature"], state["signing_public_key"])
    conn.close()

    assert rotation.rotation_promotion_request_for(setup["worker_node"]) is None
    conn = sqlite3.connect(tmp_path / "lattice.db")
    conn.execute("UPDATE fleet_nodes SET file_transport_generation=6 WHERE membership_state='active'")
    conn.commit(); conn.close()

    request = rotation.rotation_promotion_request_for(setup["worker_node"])
    assert request["action"] == "promote"
    assert request["next_generation"] == 2

    final = rotation.finalize_master_rotation(setup["worker_node"], 2)
    assert final["status"] == "finalized"
    assert final["generation"] == 7
    worker = next(m for m in final["manifest"]["members"] if m["node_id"] == setup["worker_node"])
    assert worker["file_public_key"] == next_client.public_key_text
    assert "file_next_public_key" not in worker


def test_file_stalled_rotation_alert_resolves_on_completion(tmp_path, monkeypatch):
    setup = _setup_master_db(tmp_path, monkeypatch)
    next_client = _ensure_keypair(tmp_path / "proposal2", "next_client_ed25519", "next-client")
    next_host = _ensure_keypair(tmp_path / "proposal2", "next_host_ed25519", "next-host")
    proposal = {
        "node_id": setup["worker_node"], "current_generation": 1, "next_generation": 2,
        "next_public_key": next_client.public_key_text,
        "next_host_public_key": next_host.public_key_text,
        "next_host_key_fingerprint": next_host.fingerprint,
    }
    rotation.process_master_rotation_proposal(setup["worker_node"], proposal)
    conn = sqlite3.connect(tmp_path / "lattice.db")
    conn.execute("UPDATE file_key_rotations SET proposed_at=datetime('now','-2 days')")
    conn.commit(); conn.close()

    assert rotation.rotation_promotion_request_for(setup["worker_node"]) is None
    conn = sqlite3.connect(tmp_path / "lattice.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT alert_id FROM file_key_rotations").fetchone()
    assert row["alert_id"] is not None
    alert_id = row["alert_id"]
    message = conn.execute(
        "SELECT message FROM alerts WHERE id=?", (alert_id,)
    ).fetchone()[0]
    assert "keep retrying automatically" in message
    assert "Workers screen" in message
    conn.execute("UPDATE fleet_nodes SET file_transport_generation=6 WHERE membership_state='active'")
    conn.commit(); conn.close()

    assert rotation.rotation_promotion_request_for(setup["worker_node"])["action"] == "promote"
    rotation.finalize_master_rotation(setup["worker_node"], 2)
    conn = sqlite3.connect(tmp_path / "lattice.db")
    resolved = conn.execute("SELECT resolved_at FROM alerts WHERE id=?", (alert_id,)).fetchone()[0]
    conn.close()
    assert resolved is not None


def test_file_local_promotion_requires_exact_signed_overlap(tmp_path, monkeypatch):
    shell_dir = tmp_path / "file-channel"
    rotation_dir = tmp_path / "rotation"
    monkeypatch.setenv("LATTICE_FILE_SSH_DIR", str(shell_dir))
    monkeypatch.setenv("LATTICE_FILE_ROTATION_DIR", str(rotation_dir))
    monkeypatch.setattr(rotation.os, "geteuid", lambda: 0)
    node_id = str(uuid.uuid4())
    monkeypatch.setattr(rotation, "load_node_identity", lambda: SimpleNamespace(node_id=node_id))

    current_client = ensure_file_client_identity(shell_dir)
    current_host = ensure_file_host_identity(shell_dir)
    next_client = _ensure_keypair(shell_dir, rotation.NEXT_CLIENT_NAME, "next-client")
    next_host = _ensure_keypair(shell_dir, rotation.NEXT_HOST_NAME, "next-host")
    overlap = {
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": 6,
        "members": [{
            "node_id": node_id, "hostname": "worker-node", "role": "worker", "main_user": "masteruser",
            "file_public_key": current_client.public_key_text,
            "file_host_public_key": current_host.public_key_text,
            "file_host_key_fingerprint": current_host.fingerprint,
            "file_key_generation": 1,
            "file_next_public_key": next_client.public_key_text,
            "file_next_host_public_key": next_host.public_key_text,
            "file_next_host_key_fingerprint": next_host.fingerprint,
            "file_next_key_generation": 2,
            "shell_public_key": ensure_shell_client_identity(tmp_path / "separate-shell").public_key_text,
            "shell_host_public_key": ensure_shell_host_identity(tmp_path / "separate-shell").public_key_text,
            "shell_host_key_fingerprint": ensure_shell_host_identity(tmp_path / "separate-shell").fingerprint,
            "shell_key_generation": 1,
        }],
        "revoked": [],
    }
    overlap = normalize_manifest(overlap)
    monkeypatch.setattr(rotation, "_current_manifest_for_local", lambda: overlap)
    rotation._atomic_json(rotation._promote_request_path(), {
        "action": "promote", "node_id": node_id, "next_generation": 2, "overlap_generation": 6,
    }, mode=0o644)

    assert rotation.promote_local_rotation_if_requested() == 2
    assert rotation._public_text(shell_dir / "client_ed25519.pub") == next_client.public_key_text
    assert rotation._public_text(shell_dir / "host_ed25519.pub") == next_host.public_key_text
    assert rotation.get_promoted_generation() is None
    assert rotation.confirm_local_promotion_ready() is True
    assert rotation.get_promoted_generation() == 2
