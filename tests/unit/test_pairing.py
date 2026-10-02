"""Master-side secure-enrollment tests; all network and key operations are mocked."""
from types import SimpleNamespace
import base64
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest

from lattice.file_access.keys import (
    fingerprint_ed25519_public_key,
)
from lattice.pairing import pair_worker, repair_worker_network_assignment
from lattice.onboarding import PairingError


WORKER_CERTIFICATE = (
    "-----BEGIN CERTIFICATE-----\nTEST-WORKER-CERTIFICATE\n-----END CERTIFICATE-----"
)


def _fake_ed25519(byte_value: bytes, comment: str) -> str:
    wire = (
        b"\x00\x00\x00\x0bssh-ed25519"
        + b"\x00\x00\x00\x20"
        + byte_value * 32
    )
    return (
        "ssh-ed25519 "
        + base64.b64encode(wire).decode("ascii")
        + f" {comment}"
    )


FILE_PUBLIC_KEY = _fake_ed25519(b"f", "worker-file-client")
FILE_HOST_PUBLIC_KEY = _fake_ed25519(b"h", "worker-file-host")
FILE_HOST_FINGERPRINT = fingerprint_ed25519_public_key(
    FILE_HOST_PUBLIC_KEY
)
RECOVERY_SSH_HOST_PUBLIC_KEY = _fake_ed25519(
    b"r", "worker-recovery-ssh-host"
)
RECOVERY_SSH_HOST_FINGERPRINT = fingerprint_ed25519_public_key(
    RECOVERY_SSH_HOST_PUBLIC_KEY
)

MASTER_FILE_PUBLIC_KEY = _fake_ed25519(
    b"m",
    "master-file-client",
)
MASTER_FILE_HOST_PUBLIC_KEY = _fake_ed25519(
    b"n",
    "master-file-host",
)
MASTER_FILE_HOST_FINGERPRINT = (
    fingerprint_ed25519_public_key(
        MASTER_FILE_HOST_PUBLIC_KEY
    )
)
FLEET_SIGNING_PUBLIC_KEY = _fake_ed25519(
    b"s",
    "fleet-signing",
)


@pytest.fixture(autouse=True)
def _master_role(monkeypatch):
    """This module exercises Master-side enrollment unless a test overrides it."""
    monkeypatch.setattr(
        "lattice.wizard.lifecycle.current_role",
        lambda: "master",
    )


@pytest.fixture(autouse=True)
def _mock_pairing_ssl_context(monkeypatch):
    """Pairing unit tests use fake PEM text; networking itself is mocked."""
    context = MagicMock(name="pairing_ssl_context")
    create_context = MagicMock(return_value=context)

    monkeypatch.setattr(
        "lattice.pairing.ssl.create_default_context",
        create_context,
    )

    return context, create_context


def _bound_code(pairing_id: str, hostname: str, certificate: str = WORKER_CERTIFICATE) -> str:
    secret = "ABCDEFGH"
    fingerprint = hashlib.sha256(certificate.strip().encode("utf-8")).hexdigest()
    message = f"{fingerprint}|{pairing_id}|{hostname}".encode("utf-8")
    tag = base64.b32encode(hmac.new(secret.encode("ascii"), message, hashlib.sha256).digest()).decode("ascii").rstrip("=")[:6]
    return f"{secret}-{tag}"


def _waiting_offer(
    pairing_id: str, hostname: str, ssh_user: str | None = None,
    *, certificate: str = WORKER_CERTIFICATE,
) -> MagicMock:
    response = MagicMock(status_code=200)
    resolved_user = (
        ssh_user
        or ("workeruser" if hostname == "worker-node" else "backupuser")
    )
    node_id = (
        "11111111-1111-4111-8111-111111111111"
        if hostname == "worker-node"
        else "22222222-2222-4222-8222-222222222222"
    )
    response.json.return_value = {
        "state": "waiting",
        "pairing_id": pairing_id,
        "hostname": hostname,
        "ssh_user": resolved_user,
        "worker_certificate": certificate,
        "node_id": node_id,
        "main_user": resolved_user,
        "main_uid": 1000,
        "main_gid": 1000,
        "file_public_key": FILE_PUBLIC_KEY,
        "file_host_public_key": FILE_HOST_PUBLIC_KEY,
        "file_host_key_fingerprint": FILE_HOST_FINGERPRINT,
        "file_key_generation": 1,
        "recovery_ssh_host_public_key": RECOVERY_SSH_HOST_PUBLIC_KEY,
        "recovery_ssh_host_key_fingerprint": RECOVERY_SSH_HOST_FINGERPRINT,
    }
    return response


def _paired_status(pairing_id: str, hostname: str) -> MagicMock:
    response = MagicMock(status_code=200)
    response.json.return_value = {"state": "paired", "pairing_id": pairing_id, "hostname": hostname}
    return response


def _fleet_ack(
    node_id="11111111-1111-4111-8111-111111111111",
    generation=2,
):
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "status": "applied",
        "generation": generation,
        "node_id": node_id,
    }
    return response


def _master_db(tmp_path, monkeypatch):
    monkeypatch.setenv("LATTICE_DB_PATH", str(tmp_path / "master.db"))
    monkeypatch.setenv("LATTICE_TOKEN_DIR", str(tmp_path / "tokens"))
    monkeypatch.setenv("LATTICE_PKI_DIR", str(tmp_path / "pki"))
    monkeypatch.setenv(
        "LATTICE_WORKER_CERT_DIR",
        str(tmp_path / "worker-certs"),
    )
    monkeypatch.setenv(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH",
        str(tmp_path / "file-transport-request.json"),
    )
    monkeypatch.setenv(
        "LATTICE_MOUNT_PLAN_PATH",
        str(tmp_path / "mount-plans.json"),
    )

    fake_bootstrap = SimpleNamespace(
        fleet_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        generation=1,
        node_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        hostname="master-node",
        main_user="masteruser",
        file_public_key=MASTER_FILE_PUBLIC_KEY,
        file_host_public_key=MASTER_FILE_HOST_PUBLIC_KEY,
        file_host_key_fingerprint=
            MASTER_FILE_HOST_FINGERPRINT,
        fleet_signing_public_key=
            FLEET_SIGNING_PUBLIC_KEY,
        manifest={},
        signature="test",
    )

    monkeypatch.setattr(
        "lattice.pairing.ensure_master_fleet_bootstrap",
        lambda *args, **kwargs: fake_bootstrap,
    )

    def fake_stage(conn, *, target_node_id):
        return SimpleNamespace(
            target_node_id=target_node_id,
            generation=2,
            manifest={
                "schema_version": 1,
                "fleet_id":
                    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "generation": 2,
                "members": [],
                "revoked": [],
            },
            signature=(
                "-----BEGIN SSH SIGNATURE-----\n"
                "test\n"
                "-----END SSH SIGNATURE-----\n"
            ),
        )

    def fake_commit(
        conn,
        *,
        target_node_id,
        generation,
    ):
        conn.execute(
            """
            UPDATE fleet_nodes
            SET membership_state = 'active',
                membership_generation = ?
            WHERE node_id = ?
            """,
            (generation, target_node_id),
        )

    monkeypatch.setattr(
        "lattice.pairing.stage_worker_activation",
        fake_stage,
    )
    monkeypatch.setattr(
        "lattice.pairing.commit_worker_activation",
        fake_commit,
    )

    def fake_finalize(hostname, *, worker_ip=None):
        from lattice.core.db import get_db_connection
        conn = get_db_connection()
        try:
            worker = conn.execute(
                "SELECT id FROM workers WHERE hostname=? AND removed_at IS NULL",
                (hostname,),
            ).fetchone()
            conn.execute(
                "UPDATE workers SET status='healthy', ip=?, failure_count=0 WHERE id=?",
                (worker_ip, int(worker[0])),
            )
            conn.execute(
                "UPDATE fleet_nodes SET last_known_ip=? WHERE worker_id=? "
                "AND membership_state='active'",
                (worker_ip, int(worker[0])),
            )
            conn.commit()
        finally:
            conn.close()
        mount_plan_path = __import__("pathlib").Path(
            __import__("os").environ["LATTICE_MOUNT_PLAN_PATH"]
        )
        mount_plan_path.write_text(json.dumps({"generation": 2}))
        return {"hostname": hostname, "ip": worker_ip, "status": "healthy"}

    monkeypatch.setattr(
        "lattice.pairing.reconcile_committed_worker_activation",
        fake_finalize,
    )

    from lattice.core.db import get_db_connection
    from lattice.core.migrations import run_migrations
    connection = get_db_connection()
    run_migrations(connection)
    connection.close()
    public_key = tmp_path / "lattice_ed25519.pub"
    import base64
    wire_key = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"x" * 32
    public_key.write_text(
        "ssh-ed25519 " + base64.b64encode(wire_key).decode("ascii") + " lattice-master\n"
    )
    return public_key


def test_master_adds_worker_only_after_local_approval_and_verification(
    tmp_path,
    monkeypatch,
    _mock_pairing_ssl_context,
):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    confirm = MagicMock(status_code=202)
    assignment = MagicMock(status_code=202, text="accepted")
    inventory = MagicMock(status_code=200)

    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing._automatic_network_assignment", return_value={"address": "10.77.0.201", "prefix": 24, "gateway": "10.77.0.1", "dns": ["10.77.0.1"]}), \
         patch("lattice.pairing._wait_for_worker_at_address"), \
         patch(
             "lattice.pairing.httpx.post",
             side_effect=[
                 confirm,
                 assignment,
                 _fleet_ack(),
             ],
         ) as post, \
         patch("lattice.pairing.httpx.get", side_effect=[_waiting_offer("pairing-id-123456789", "worker-node"), _paired_status("pairing-id-123456789", "worker-node"), inventory]) as get:
        result = pair_worker(
            hostname="worker-node", worker_ip="10.77.0.103",
            pairing_id="pairing-id-123456789", code=_bound_code("pairing-id-123456789", "worker-node"), ssh_user="workeruser",
            master_hostname="master-node", master_ip="10.77.0.88", ssh_verifier=lambda *_: "SHA256:test",
        )

    assert result == {"hostname": "worker-node", "ip": "10.77.0.201", "ssh_user": "workeruser", "status": "paired"}
    certificate_path = tmp_path / "worker-certs" / "worker-node.crt"
    assert certificate_path.read_text() == WORKER_CERTIFICATE + "\n"
    assert get.call_args_list[0].args[0] == "https://10.77.0.103:9999/v1/pairing/status"
    assert get.call_args_list[0].kwargs["verify"] is False
    assert post.call_args_list[0].args[0] == (
        "https://worker-node.local:9999/v1/pairing/confirm"
    )

    sent_pairing = post.call_args_list[0].kwargs["json"]

    assert sent_pairing["fleet_id"] == (
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    assert sent_pairing["master_node_id"] == (
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    )
    assert (
        sent_pairing["fleet_signing_public_key"]
        == FLEET_SIGNING_PUBLIC_KEY
    )

    verify_context, create_context = _mock_pairing_ssl_context

    create_context.assert_any_call(
        cafile=str(certificate_path)
    )

    assert (
        post.call_args_list[0].kwargs["verify"]
        is verify_context
    )
    assert get.call_args_list[1].args[0] == "https://worker-node.local:9999/v1/pairing/status"
    assert get.call_args_list[2].args[0] == "https://worker-node.local:9999/v1/services"
    assert post.call_args_list[1].args[0] == "https://worker-node.local:9999/v1/network/assign"
    assert post.call_args_list[2].args[0] == (
        "https://worker-node.local:9999/v1/fleet/manifest"
    )


def test_master_does_not_add_worker_before_local_approval(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    waiting = MagicMock(status_code=200)
    waiting.json.return_value = {"state": "awaiting_approval", "pairing_id": "pairing-id-123456789", "hostname": "backup-node"}

    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.post", return_value=MagicMock(status_code=202)), \
         patch("lattice.pairing.httpx.get", side_effect=[_waiting_offer("pairing-id-123456789", "backup-node"), waiting]):
        with pytest.raises(PairingError, match="not approved"):
            pair_worker(
                hostname="backup-node", worker_ip="10.77.0.85", pairing_id="pairing-id-123456789",
                code=_bound_code("pairing-id-123456789", "backup-node"), ssh_user="backupuser", master_ip="10.77.0.88",
                approval_wait_attempts=1,
            )


def test_master_does_not_record_worker_when_token_verification_fails(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing._revoke_remote_pairing", return_value=True) as cleanup, \
         patch("lattice.pairing.httpx.post", return_value=MagicMock(status_code=202)), \
         patch("lattice.pairing.httpx.get", side_effect=[_waiting_offer("pairing-id-123456789", "backup-node"), _paired_status("pairing-id-123456789", "backup-node"), MagicMock(status_code=403)]):
        with pytest.raises(PairingError, match="verification"):
            pair_worker(
                hostname="backup-node", worker_ip="10.77.0.85", pairing_id="pairing-id-123456789",
                code=_bound_code("pairing-id-123456789", "backup-node"), ssh_user="backupuser", master_ip="10.77.0.88",
            )
    cleanup.assert_called_once()
    assert not (tmp_path / "worker-certs" / "backup-node.crt").exists()
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    assert conn.execute("SELECT 1 FROM workers WHERE hostname = 'backup-node'").fetchone() is None
    conn.close()


def test_master_assigns_a_safe_pool_address_after_pairing(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.200"))
    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing._automatic_network_assignment", return_value={"address": "10.77.0.201", "prefix": 24, "gateway": "10.77.0.1", "dns": ["10.77.0.1"]}), \
         patch("lattice.pairing._wait_for_worker_at_address"), \
         patch(
             "lattice.pairing.httpx.post",
             side_effect=[
                 MagicMock(status_code=202),
                 MagicMock(status_code=202, text="accepted"),
                 _fleet_ack(),
             ],
         ) as post, \
         patch("lattice.pairing.httpx.get", side_effect=[_waiting_offer("pairing-id-123456789", "worker-node"), _paired_status("pairing-id-123456789", "worker-node"), MagicMock(status_code=200), MagicMock(status_code=200)]):
        result = pair_worker(
            hostname="worker-node", worker_ip="10.77.0.103", pairing_id="pairing-id-123456789",
            code=_bound_code("pairing-id-123456789", "worker-node"), ssh_user="workeruser", master_ip="10.77.0.200", ssh_verifier=lambda *_: "SHA256:test",
        )
    assert result["ip"] == "10.77.0.201"
    assert post.call_count == 3


def test_master_does_not_record_worker_when_ssh_access_cannot_be_verified(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.post", return_value=MagicMock(status_code=202)), \
         patch("lattice.pairing.httpx.get", side_effect=[_waiting_offer("pairing-id-123456789", "backup-node"), _paired_status("pairing-id-123456789", "backup-node"), MagicMock(status_code=200)]):
        with pytest.raises(PairingError, match="SSH access verification failed"):
            pair_worker(
                hostname="backup-node", worker_ip="10.77.0.85", pairing_id="pairing-id-123456789",
                code=_bound_code("pairing-id-123456789", "backup-node"), ssh_user="backupuser", master_ip="10.77.0.88",
                ssh_verifier=lambda *_: (_ for _ in ()).throw(PairingError("SSH access verification failed")),
            )


def test_master_rejects_invalid_ssh_user_from_protected_confirmation(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    confirm = MagicMock(status_code=202)
    confirm.json.return_value = {"ssh_user": "bad user!"}

    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.post", return_value=confirm), \
         patch("lattice.pairing.httpx.get", return_value=_waiting_offer("pairing-id-123456789", "backup-node")):
        with pytest.raises(PairingError, match="invalid SSH user"):
            pair_worker(
                hostname="backup-node",
                worker_ip="10.77.0.85",
                pairing_id="pairing-id-123456789",
                code=_bound_code("pairing-id-123456789", "backup-node"),
                master_ip="10.77.0.88",
            )

def test_invalid_fresh_pairing_cannot_erase_unsigned_incomplete_record(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    from lattice.core.db import get_db_connection

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO workers (hostname,status,ip,ssh_user) VALUES (?,?,?,?)",
        ("backup-node", "needs_attention", "10.77.0.85", "backupuser"),
    )
    conn.commit(); conn.close()

    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.200"))
    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.get", return_value=_waiting_offer("pairing-id-123456789", "backup-node")), \
         patch("lattice.pairing.httpx.post") as post:
        with pytest.raises(PairingError, match="not authenticated"):
            pair_worker(
                hostname="backup-node", worker_ip="10.77.0.85",
                pairing_id="pairing-id-123456789", code="ABCDEFGH-BADTAG",
                ssh_user="backupuser", master_ip="10.77.0.200",
            )
    post.assert_not_called()
    conn = get_db_connection()
    row = conn.execute(
        "SELECT status,ip FROM workers WHERE hostname='backup-node'"
    ).fetchone()
    conn.close()
    assert tuple(row) == ("needs_attention", "10.77.0.85")


def test_removed_worker_row_is_reactivated_only_after_verification(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO workers (hostname, status, removed_at) VALUES (?, 'removed', datetime('now'))",
        ("worker-node",),
    )
    conn.commit()
    conn.close()
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing._automatic_network_assignment", return_value={"address": "10.77.0.201", "prefix": 24, "gateway": "10.77.0.1", "dns": []}), \
         patch("lattice.pairing._wait_for_worker_at_address"), \
         patch(
             "lattice.pairing.httpx.post",
             side_effect=[
                 MagicMock(status_code=202),
                 MagicMock(status_code=202, text="accepted"),
                 _fleet_ack(),
             ],
         ), \
         patch("lattice.pairing.httpx.get", side_effect=[_waiting_offer("pairing-id-123456789", "worker-node"), _paired_status("pairing-id-123456789", "worker-node"), MagicMock(status_code=200), MagicMock(status_code=200)]):
        pair_worker(
            hostname="worker-node", worker_ip="10.77.0.103",
            pairing_id="pairing-id-123456789", code=_bound_code("pairing-id-123456789", "worker-node"),
            ssh_user="workeruser", master_ip="10.77.0.88",
            ssh_verifier=lambda *_: "SHA256:test",
        )
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT status, removed_at FROM workers WHERE hostname = ?", ("worker-node",)
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert tuple(rows[0]) == ("healthy", None)


def test_master_rejects_substituted_worker_certificate_before_sending_secrets(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    legitimate = _waiting_offer("pairing-id-123456789", "backup-node")
    payload = legitimate.json.return_value.copy()
    payload["worker_certificate"] = (
        "-----BEGIN CERTIFICATE-----\nATTACKER-CERTIFICATE\n-----END CERTIFICATE-----"
    )
    substituted = MagicMock(status_code=200)
    substituted.json.return_value = payload
    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.post") as post, \
         patch("lattice.pairing.httpx.get", return_value=substituted):
        with pytest.raises(PairingError, match="not authenticated by the pairing code"):
            pair_worker(
                hostname="backup-node", worker_ip="10.77.0.85",
                pairing_id="pairing-id-123456789", code=_bound_code("pairing-id-123456789", "backup-node"),
                ssh_user="backupuser", master_ip="10.77.0.88",
            )
    post.assert_not_called()


def test_master_records_worker_file_identity_after_full_pairing(
    tmp_path,
    monkeypatch,
):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(
        master=SimpleNamespace(ip="10.77.0.88")
    )

    with patch(
        "lattice.pairing.load_config",
        return_value=config,
    ), patch(
        "lattice.pairing.ensure_lattice_ssh_key",
        return_value=(tmp_path / "private", public_key),
    ), patch(
        "lattice.pairing._automatic_network_assignment",
        return_value={
            "address": "10.77.0.201",
            "prefix": 24,
            "gateway": "10.77.0.1",
            "dns": [],
        },
    ), patch(
        "lattice.pairing._wait_for_worker_at_address",
    ), patch(
        "lattice.pairing.httpx.post",
        side_effect=[
            MagicMock(status_code=202),
            MagicMock(status_code=202, text="accepted"),
            _fleet_ack(),
        ],
    ), patch(
        "lattice.pairing.httpx.get",
        side_effect=[
            _waiting_offer(
                "pairing-id-123456789",
                "worker-node",
            ),
            _paired_status(
                "pairing-id-123456789",
                "worker-node",
            ),
            MagicMock(status_code=200),
        ],
    ):
        pair_worker(
            hostname="worker-node",
            worker_ip="10.77.0.103",
            pairing_id="pairing-id-123456789",
            code=_bound_code(
                "pairing-id-123456789",
                "worker-node",
            ),
            ssh_user="workeruser",
            master_ip="10.77.0.88",
            ssh_verifier=lambda *_: "SHA256:test",
        )

    from lattice.core.db import get_db_connection

    conn = get_db_connection()
    row = conn.execute(
        """
        SELECT
            f.hostname,
            f.main_user,
            f.membership_state,
            f.membership_generation,
            f.last_known_ip,
            f.file_key_generation
        FROM fleet_nodes f
        """
    ).fetchone()
    conn.close()

    assert tuple(row) == (
        "worker-node",
        "workeruser",
        "active",
        2,
        "10.77.0.201",
        1,
    )

    mount_plan = json.loads((tmp_path / "mount-plans.json").read_text())
    assert mount_plan["generation"] == 2


def test_active_pool_interface_follows_current_master_address(monkeypatch):
    import lattice.pairing as pairing

    class Result:
        returncode = 0
        stderr = ""
        stdout = (
            "2: old0    inet 10.0.0.10/24 brd 10.0.0.255 scope global old0\n"
            "3: wlx-live inet 10.77.0.200/24 brd 10.77.0.255 scope global wlx-live\n"
        )

    monkeypatch.setattr(pairing.subprocess, "run", lambda *a, **k: Result())
    pool = SimpleNamespace(network="10.77.0.0/24", interface="old0")
    assert pairing._active_pool_interface(pool, "10.77.0.200") == "wlx-live"


def test_active_pool_interface_refuses_when_master_address_is_not_active(monkeypatch):
    import lattice.pairing as pairing

    class Result:
        returncode = 0
        stderr = ""
        stdout = "2: old0 inet 10.77.0.50/24 brd 10.77.0.255 scope global old0\n"

    monkeypatch.setattr(pairing.subprocess, "run", lambda *a, **k: Result())
    pool = SimpleNamespace(network="10.77.0.0/24", interface="old0")
    with pytest.raises(PairingError, match="not active"):
        pairing._active_pool_interface(pool, "10.77.0.200")


def test_fresh_pairing_can_discard_unsigned_incomplete_previous_enrollment(
    tmp_path, monkeypatch,
):
    import lattice.pairing as pairing
    _master_db(tmp_path, monkeypatch)
    from lattice.core.db import get_db_connection

    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO workers (hostname,status,ip,ssh_user) VALUES (?,?,?,?)",
        ("backup-node", "needs_attention", "10.77.0.85", "backupuser"),
    )
    worker_id = cur.lastrowid
    conn.execute(
        "INSERT INTO services (name,worker_id,type,status) VALUES (?,?,?,?)",
        ("lattice-worker.service", worker_id, "systemd", "active"),
    )
    conn.commit(); conn.close()

    token = tmp_path / "tokens" / "backup-node.token"
    token.parent.mkdir(parents=True, exist_ok=True)
    token.write_text("stale-token\n")
    cert = tmp_path / "worker-certs" / "backup-node.crt"
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_text(WORKER_CERTIFICATE + "\n")

    assert pairing._discard_unsigned_incomplete_enrollment("backup-node") is True

    conn = get_db_connection()
    assert conn.execute(
        "SELECT 1 FROM workers WHERE hostname='backup-node'"
    ).fetchone() is None
    assert conn.execute(
        "SELECT 1 FROM services WHERE worker_id=?", (worker_id,)
    ).fetchone() is None
    conn.close()
    assert not token.exists()
    assert not cert.exists()


def test_fresh_pairing_never_discards_worker_with_fleet_identity(tmp_path, monkeypatch):
    import lattice.pairing as pairing
    _master_db(tmp_path, monkeypatch)
    from lattice.core.db import get_db_connection

    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO workers (hostname,status,ip,ssh_user) VALUES (?,?,?,?)",
        ("backup-node", "needs_attention", "10.77.0.85", "backupuser"),
    )
    worker_id = cur.lastrowid
    conn.execute(
        """INSERT INTO fleet_nodes
           (node_id,worker_id,hostname,role,main_user,main_uid,main_gid,membership_state,last_known_ip)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        ("22222222-2222-4222-8222-222222222222", worker_id, "backup-node",
         "worker", "backupuser", 1000, 1000, "active", "10.77.0.85"),
    )
    conn.commit(); conn.close()

    assert pairing._discard_unsigned_incomplete_enrollment("backup-node") is False
    conn = get_db_connection()
    assert conn.execute(
        "SELECT 1 FROM workers WHERE hostname='backup-node'"
    ).fetchone() is not None
    conn.close()


def test_address_probe_uses_thomas_habets_interface_flag_and_reply_semantics(monkeypatch):
    import lattice.pairing as pairing
    calls = []

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return Result()

    monkeypatch.setattr(pairing.subprocess, "run", fake_run)
    assert pairing._address_is_in_use("wlan0", "10.77.0.201") is True
    cmd = calls[0][0]
    assert "-i" in cmd
    assert "-I" not in cmd
    assert cmd[cmd.index("-i") + 1] == "wlan0"


def test_address_probe_treats_no_reply_as_free(monkeypatch):
    import lattice.pairing as pairing

    class Result:
        returncode = 1
        stdout = ""
        stderr = ""

    monkeypatch.setattr(pairing.subprocess, "run", lambda *a, **k: Result())
    assert pairing._address_is_in_use("wlan0", "10.77.0.201") is False


def test_address_probe_does_not_hide_arping_command_errors(monkeypatch):
    import lattice.pairing as pairing

    class Result:
        returncode = 1
        stdout = ""
        stderr = "arping: invalid interface"

    monkeypatch.setattr(pairing.subprocess, "run", lambda *a, **k: Result())
    with pytest.raises(PairingError, match="invalid interface"):
        pairing._address_is_in_use("bad0", "10.77.0.201")


def _seed_active_worker_for_network_repair(tmp_path, monkeypatch, *, active=True):
    _master_db(tmp_path, monkeypatch)
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    cur = conn.execute(
        "INSERT INTO workers (hostname,status,ip,ssh_user) VALUES (?,?,?,?)",
        ("worker-node", "healthy", "10.77.0.103", "workeruser"),
    )
    worker_id = cur.lastrowid
    if active:
        conn.execute(
            """INSERT INTO fleet_nodes
               (node_id,worker_id,hostname,role,main_user,main_uid,main_gid,membership_state,last_known_ip)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            ("11111111-1111-4111-8111-111111111111", worker_id, "worker-node",
             "worker", "workeruser", 1000, 1000, "active", "10.77.0.103"),
        )
    conn.commit(); conn.close()
    cert_dir = tmp_path / "worker-certs"; cert_dir.mkdir(exist_ok=True)
    (cert_dir / "worker-node.crt").write_text(WORKER_CERTIFICATE + "\n")
    token_dir = tmp_path / "tokens"; token_dir.mkdir(exist_ok=True)
    token_path = token_dir / "worker-node.token"
    token_path.write_text("t" * 48 + "\n")
    token_path.chmod(0o600)
    return worker_id


def test_network_repair_finishes_existing_paired_worker(tmp_path, monkeypatch):
    worker_id = _seed_active_worker_for_network_repair(
        tmp_path, monkeypatch, active=False
    )
    config = SimpleNamespace(
        master=SimpleNamespace(ip="10.77.0.200"),
        wire_format=SimpleNamespace(port=9999),
    )
    monkeypatch.setattr("lattice.pairing.load_config", lambda: config)
    monkeypatch.setattr(
        "lattice.pairing._automatic_network_assignment",
        lambda _master_ip, **kwargs: {"address":"10.77.0.201","prefix":24,"gateway":"10.77.0.254","dns":["10.77.0.254"]},
    )
    monkeypatch.setattr("lattice.pairing._wait_for_worker_at_address", lambda *a, **k: None)

    identity = _waiting_offer("ignored-pairing-id", "worker-node").json.return_value
    identity_response = MagicMock(status_code=200)
    identity_response.json.return_value = identity
    monkeypatch.setattr("lattice.pairing.httpx.get", lambda *a, **k: identity_response)
    network_response = MagicMock(status_code=202, text="accepted")
    activation_response = _fleet_ack()
    posts = iter([network_response, activation_response])
    monkeypatch.setattr("lattice.pairing.httpx.post", lambda *a, **k: next(posts))

    result = repair_worker_network_assignment("worker-node")
    assert result["old_ip"] == "10.77.0.103"
    assert result["ip"] == "10.77.0.201"
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    row = conn.execute("SELECT status,ip FROM workers WHERE id=?", (worker_id,)).fetchone()
    fleet = conn.execute(
        "SELECT last_known_ip,membership_state FROM fleet_nodes WHERE worker_id=?",
        (worker_id,),
    ).fetchone()
    conn.close()
    assert tuple(row) == ("healthy", "10.77.0.201")
    assert tuple(fleet) == ("10.77.0.201", "active")


def test_network_repair_failure_stays_needs_attention(tmp_path, monkeypatch):
    worker_id = _seed_active_worker_for_network_repair(tmp_path, monkeypatch)
    config = SimpleNamespace(
        master=SimpleNamespace(ip="10.77.0.200"),
        wire_format=SimpleNamespace(port=9999),
    )
    monkeypatch.setattr("lattice.pairing.load_config", lambda: config)
    identity = _waiting_offer("ignored-pairing-id", "worker-node").json.return_value
    identity_response = MagicMock(status_code=200)
    identity_response.json.return_value = identity
    monkeypatch.setattr("lattice.pairing.httpx.get", lambda *a, **k: identity_response)
    monkeypatch.setattr(
        "lattice.pairing._automatic_network_assignment",
        lambda _master_ip, **kwargs: (_ for _ in ()).throw(PairingError("ARP probe failed")),
    )
    with pytest.raises(PairingError, match="ARP probe failed"):
        repair_worker_network_assignment("worker-node")
    from lattice.core.db import get_db_connection
    conn = get_db_connection()
    row = conn.execute("SELECT status,ip FROM workers WHERE id=?", (worker_id,)).fetchone()
    conn.close()
    assert tuple(row) == ("needs_attention", "10.77.0.103")


def test_recovery_ssh_verifier_uses_only_pinned_authenticated_host_key(tmp_path):
    from lattice.pairing import verify_worker_ssh

    private_key = tmp_path / "lattice_ed25519"
    private_key.write_text("private")
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    fingerprint = verify_worker_ssh(
        "10.77.0.103",
        "workeruser",
        private_key,
        "10.77.0.200",
        RECOVERY_SSH_HOST_PUBLIC_KEY,
        "worker-node",
        runner=runner,
    )

    assert fingerprint == RECOVERY_SSH_HOST_FINGERPRINT
    known_hosts = private_key.parent / "known_hosts"
    assert known_hosts.read_text().strip() == (
        "worker-node "
        + " ".join(RECOVERY_SSH_HOST_PUBLIC_KEY.split()[:2])
    )
    joined = " ".join(commands[0])
    assert "StrictHostKeyChecking=yes" in joined
    assert "StrictHostKeyChecking=accept-new" not in joined
    assert "HostKeyAlias=worker-node" in joined


def test_pairing_rejects_mismatched_recovery_ssh_fingerprint(tmp_path, monkeypatch):
    public_key = _master_db(tmp_path, monkeypatch)
    config = SimpleNamespace(master=SimpleNamespace(ip="10.77.0.88"))
    offer = _waiting_offer("pairing-id-123456789", "worker-node")
    offer.json.return_value["recovery_ssh_host_key_fingerprint"] = "SHA256:wrong"

    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.get", return_value=offer):
        with pytest.raises(PairingError, match="fingerprint does not match"):
            pair_worker(
                hostname="worker-node",
                worker_ip="10.77.0.103",
                pairing_id="pairing-id-123456789",
                code=_bound_code("pairing-id-123456789", "worker-node"),
                ssh_user="workeruser",
                master_ip="10.77.0.88",
            )


def test_existing_pair_can_upgrade_recovery_host_key_over_pinned_tls(tmp_path, monkeypatch):
    from lattice.pairing import refresh_worker_recovery_ssh_identity
    from lattice.core.db import get_db_connection

    public_key = _master_db(tmp_path, monkeypatch)
    certificate = tmp_path / "worker-certs" / "worker-node.crt"
    certificate.parent.mkdir(parents=True, exist_ok=True)
    certificate.write_text(WORKER_CERTIFICATE + "\n")

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO workers (hostname, status, ssh_user, ip, last_heartbeat_at) "
        "VALUES ('worker-node', 'healthy', 'workeruser', '10.77.0.201', datetime('now'))"
    )
    conn.commit()
    conn.close()

    identity = MagicMock(status_code=200)
    identity.json.return_value = {
        "hostname": "worker-node",
        "recovery_ssh_host_public_key": RECOVERY_SSH_HOST_PUBLIC_KEY,
        "recovery_ssh_host_key_fingerprint": RECOVERY_SSH_HOST_FINGERPRINT,
    }
    config = SimpleNamespace(wire_format=SimpleNamespace(port=9999))

    with patch("lattice.pairing.load_config", return_value=config), \
         patch("lattice.core.worker_auth.read_worker_token", return_value="token-value"), \
         patch("lattice.pairing.ensure_lattice_ssh_key", return_value=(tmp_path / "private", public_key)), \
         patch("lattice.pairing.httpx.get", return_value=identity) as get:
        fingerprint = refresh_worker_recovery_ssh_identity("worker-node")

    assert fingerprint == RECOVERY_SSH_HOST_FINGERPRINT
    assert "worker-node ssh-ed25519" in (tmp_path / "known_hosts").read_text()
    assert get.call_args.args[0] == "https://worker-node.local:9999/v1/fleet/identity"
    assert get.call_args.kwargs["headers"]["Authorization"] == "Bearer token-value"

    conn = get_db_connection()
    stored = conn.execute(
        "SELECT ssh_host_key_fingerprint FROM workers WHERE hostname='worker-node'"
    ).fetchone()[0]
    conn.close()
    assert stored == RECOVERY_SSH_HOST_FINGERPRINT
