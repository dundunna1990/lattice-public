"""Tests for worker-first onboarding and one-time-code pairing."""
import base64
import json
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from lattice.daemon.api.worker_app import app
from lattice.file_access.keys import (
    fingerprint_ed25519_public_key,
)
from lattice.onboarding import (
    PairingError,
    confirm_worker_pairing,
    get_public_pairing_status,
    get_worker_master_endpoint,
    prepare_worker_pairing,
)
from datetime import datetime, timedelta, timezone


@pytest.fixture
def pairing_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("LATTICE_PAIRING_STATE_PATH", str(tmp_path / "pairing.json"))
    monkeypatch.setenv("LATTICE_TOKEN_DIR", str(tmp_path / "tokens"))
    monkeypatch.setenv("LATTICE_AUTHORIZED_KEYS_PATH", str(tmp_path / "authorized_keys"))
    monkeypatch.setenv("LATTICE_PKI_DIR", str(tmp_path / "pki"))
    monkeypatch.setenv(
        "LATTICE_NODE_IDENTITY_PATH",
        str(tmp_path / "node-identity.json"),
    )
    monkeypatch.setenv(
        "LATTICE_FILE_SSH_DIR",
        str(tmp_path / "file-ssh"),
    )
    recovery_host_key = tmp_path / "ssh_host_ed25519_key.pub"
    recovery_host_key.write_text(_public_key(b"r", "worker-recovery-host") + "\n")
    recovery_host_key.chmod(0o644)
    monkeypatch.setenv(
        "LATTICE_RECOVERY_SSH_HOST_KEY_PATH",
        str(recovery_host_key),
    )

    # These tests simulate Worker and Backup nodes while actually running on
    # the local test host. Their fixture usernames do not necessarily exist on this host,
    # so supply harmless fake UID/GID values only inside the test.
    from lattice.file_access import profile as file_profile

    real_ensure_node_identity = file_profile.ensure_node_identity

    def ensure_test_node_identity(main_user, *, path=None):
        return real_ensure_node_identity(
            main_user,
            path=path,
            main_uid=1000,
            main_gid=1000,
        )

    monkeypatch.setattr(
        file_profile,
        "ensure_node_identity",
        ensure_test_node_identity,
    )

    monkeypatch.setenv("LATTICE_PAIRING_TEST_DIRECT", "1")
    return tmp_path


def _public_key(
    fill: bytes = b"x",
    comment: str = "lattice-master",
) -> str:
    wire_key = (
        b"\x00\x00\x00\x0bssh-ed25519"
        + b"\x00\x00\x00\x20"
        + fill * 32
    )
    return (
        "ssh-ed25519 "
        + base64.b64encode(wire_key).decode("ascii")
        + f" {comment}"
    )


def _pairing_request(offer):
    master_file_host_key = _public_key(
        b"h",
        "master-file-host",
    )

    return {
        "pairing_id": offer.pairing_id,
        "code": offer.code,
        "master_hostname": "master-node",
        "master_ip": "10.77.0.88",
        "master_public_key": _public_key(),
        "fleet_id":
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "master_node_id":
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "master_file_public_key":
            _public_key(b"f", "master-file-client"),
        "master_file_host_public_key":
            master_file_host_key,
        "master_file_host_key_fingerprint":
            fingerprint_ed25519_public_key(
                master_file_host_key
            ),
        "fleet_signing_public_key":
            _public_key(b"s", "fleet-signing"),
        "worker_token": "x" * 48,
        "master_ca_certificate": (
            "-----BEGIN CERTIFICATE-----\nTEST-MASTER-CA\n-----END CERTIFICATE-----"
        ),
    }


def test_worker_offer_never_persists_or_publishes_the_code(pairing_paths):
    offer = prepare_worker_pairing("worker-node", "masteruser")

    state_text = (pairing_paths / "pairing.json").read_text()
    public_status = get_public_pairing_status()
    worker_certificate = public_status["worker_certificate"]

    assert offer.code not in state_text
    assert offer.code not in json.dumps(public_status)
    assert "code_salt" not in public_status
    assert "certificate_proof" not in public_status
    assert worker_certificate.startswith("-----BEGIN CERTIFICATE-----")
    assert public_status["state"] == "waiting"
    assert public_status["pairing_id"] == offer.pairing_id
    assert public_status["hostname"] == "worker-node"
    assert public_status["expires_at"] == offer.expires_at
    assert public_status["worker_certificate"] == worker_certificate

    assert public_status["node_id"] == offer.node_id
    assert public_status["main_user"] == "masteruser"
    assert public_status["main_uid"] > 0
    assert public_status["main_gid"] >= 0
    assert public_status["file_public_key"].startswith("ssh-ed25519 ")
    assert public_status["file_host_public_key"].startswith("ssh-ed25519 ")
    assert public_status["file_host_key_fingerprint"].startswith("SHA256:")
    assert public_status["file_key_generation"] == 1


def test_pairing_rejects_bad_code_without_installing_anything(pairing_paths):
    offer = prepare_worker_pairing("worker-node", "masteruser")
    request = _pairing_request(offer)
    request["code"] = "WRONG-CODE"

    with pytest.raises(PairingError, match="incorrect"):
        confirm_worker_pairing(**request)

    assert not (pairing_paths / "authorized_keys").exists()
    assert not (pairing_paths / "tokens").exists()


def test_production_request_waits_for_local_approval_without_installing_credentials(pairing_paths, monkeypatch):
    monkeypatch.delenv("LATTICE_PAIRING_TEST_DIRECT")
    offer = prepare_worker_pairing("worker-node", "masteruser")

    result = confirm_worker_pairing(**_pairing_request(offer))

    assert result["state"] == "awaiting_approval"
    assert result["worker_certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert get_public_pairing_status()["state"] == "awaiting_approval"
    assert not (pairing_paths / "authorized_keys").exists()
    assert not (pairing_paths / "tokens").exists()


def test_pairing_installs_restricted_key_and_private_token(pairing_paths):
    offer = prepare_worker_pairing("worker-node", "masteruser")

    result = confirm_worker_pairing(**_pairing_request(offer))

    assert result["state"] == "paired"
    key_text = (pairing_paths / "authorized_keys").read_text()
    assert 'from="10.77.0.88/32"' in key_text
    assert "no-pty" in key_text
    token_path = pairing_paths / "tokens" / "worker-node.token"
    assert token_path.read_text().strip() == "x" * 48
    assert (token_path.stat().st_mode & 0o777) == 0o600
    assert get_public_pairing_status()["state"] == "paired"
    assert get_worker_master_endpoint() == {
        "ip": "10.77.0.88",
        "port": 8080,
        "hostname": "master-node",
    }

    bootstrap = json.loads(
        (pairing_paths / "fleet-bootstrap.json").read_text()
    )
    assert bootstrap["fleet_id"] == (
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    )
    assert bootstrap["master_node_id"] == (
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    )
    assert bootstrap[
        "fleet_signing_public_key"
    ].startswith("ssh-ed25519 ")


@pytest_asyncio.fixture
async def pairing_client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def test_pairing_api_status_and_confirm(pairing_paths, pairing_client):
    offer = prepare_worker_pairing("backup-node", "backupuser")

    status_response = await pairing_client.get("/v1/pairing/status")
    assert status_response.status_code == 200
    assert "code" not in status_response.json()

    confirm_response = await pairing_client.post("/v1/pairing/confirm", json=_pairing_request(offer))
    assert confirm_response.status_code == 202
    assert confirm_response.json()["state"] == "paired"

    after_response = await pairing_client.get("/v1/pairing/status")
    assert after_response.status_code == 200
    assert after_response.json()["state"] == "paired"


@pytest.mark.parametrize(
    "field,value,match",
    [
        ("master_public_key", _public_key() + "\nssh-ed25519 AAAA attacker", "single line"),
        ("worker_token", "x" * 32 + "\nextra", "single line"),
    ],
)
def test_pairing_rejects_multiline_credentials(pairing_paths, field, value, match):
    offer = prepare_worker_pairing("worker-node", "masteruser")
    request = _pairing_request(offer)
    request[field] = value
    with pytest.raises(PairingError, match=match):
        confirm_worker_pairing(**request)


def test_pending_local_approval_expires_and_scrubs_secrets(pairing_paths, monkeypatch):
    monkeypatch.delenv("LATTICE_PAIRING_TEST_DIRECT")
    offer = prepare_worker_pairing("worker-node", "masteruser")
    confirm_worker_pairing(**_pairing_request(offer))
    path = pairing_paths / "pairing.json"
    state = json.loads(path.read_text())
    state["approval_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    path.write_text(json.dumps(state))

    assert get_public_pairing_status() is None
    saved = json.loads(path.read_text())
    assert saved["state"] == "expired"
    assert "worker_token" not in saved
    assert "master_public_key" not in saved


def test_bad_pairing_codes_are_throttled_per_source_and_session_can_be_reissued(pairing_paths):
    offer = prepare_worker_pairing("worker-node", "masteruser")
    request = _pairing_request(offer)
    request["code"] = "WRONG-CODE"
    with pytest.raises(PairingError, match="incorrect"):
        confirm_worker_pairing(**request, source_ip="10.77.0.50")
    with pytest.raises(PairingError, match="retry in"):
        confirm_worker_pairing(**request, source_ip="10.77.0.50")

    for suffix in range(51, 55):
        with pytest.raises(PairingError):
            confirm_worker_pairing(**request, source_ip=f"10.77.0.{suffix}")
    assert get_public_pairing_status() is None

    replacement = prepare_worker_pairing("worker-node", "masteruser")
    assert replacement.pairing_id != offer.pairing_id
    assert replacement.code != offer.code
    assert get_public_pairing_status()["state"] == "waiting"
