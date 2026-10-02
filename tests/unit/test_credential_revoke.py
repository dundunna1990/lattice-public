"""Credential revocation is generation-bound, expiring, and symlink-safe."""

from datetime import datetime, timedelta, timezone
import json
import os
from types import SimpleNamespace

import pytest

from lattice import credential_revoke


@pytest.fixture
def revoke_paths(tmp_path, monkeypatch):
    home = tmp_path / "home"
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    token_dir = tmp_path / "tokens"
    token_dir.mkdir(mode=0o700)
    sudoers_dir = tmp_path / "sudoers.d"
    sudoers_dir.mkdir(mode=0o700)
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir(mode=0o700)
    state = tmp_path / "pairing.json"
    request = tmp_path / "revoke-request.json"
    endpoint = tmp_path / "master-endpoint.json"
    recovery_authority = tmp_path / "recovery-authority.json"
    network_authority = tmp_path / "network-assignment-authority.json"
    uid, gid = os.getuid(), os.getgid()
    account = SimpleNamespace(pw_uid=uid, pw_gid=gid, pw_dir=str(home))
    group = SimpleNamespace(gr_gid=gid)
    monkeypatch.setattr(credential_revoke, "STATE", state)
    monkeypatch.setattr(credential_revoke, "REQUEST", request)
    monkeypatch.setattr(credential_revoke, "TOKEN_DIR", token_dir)
    monkeypatch.setattr(credential_revoke, "SUDOERS_DIR", sudoers_dir)
    monkeypatch.setattr(credential_revoke, "MASTER_ENDPOINT", endpoint)
    monkeypatch.setattr(credential_revoke, "MASTER_CA", pki_dir / "ca.crt")
    monkeypatch.setattr(credential_revoke, "RECOVERY_AUTHORITY", recovery_authority)
    monkeypatch.setattr(credential_revoke, "NETWORK_ASSIGNMENT_AUTHORITY", network_authority)
    monkeypatch.setattr(credential_revoke.pwd, "getpwnam", lambda _name: account)
    monkeypatch.setattr(credential_revoke.grp, "getgrnam", lambda _name: group)
    monkeypatch.setattr(credential_revoke.os, "geteuid", lambda: 0)
    payload = {
        "state": "paired",
        "pairing_id": "generation-one",
        "hostname": "worker-one",
        "ssh_user": "masteruser",
        "master_key_blob": "MASTERKEYBLOB",
    }
    state.write_text(json.dumps(payload) + "\n")
    state.chmod(0o600)
    endpoint.write_text('{"ip":"10.77.0.2"}\n')
    endpoint.chmod(0o600)
    return SimpleNamespace(
        home=home, ssh_dir=ssh_dir, state=state, request=request, endpoint=endpoint,
    )


def test_revocation_removes_only_exact_key_and_leaves_tombstone(revoke_paths):
    authorized = revoke_paths.ssh_dir / "authorized_keys"
    authorized.write_text(
        'command="safe" ssh-ed25519 MASTERKEYBLOB lattice\n'
        '# mention MASTERKEYBLOB without being that key\n'
        'ssh-ed25519 OTHERKEY personal\n'
    )
    authorized.chmod(0o600)

    credential_revoke.queue_local_revoke("worker-one")
    credential_revoke.revoke()

    remaining = authorized.read_text()
    assert "ssh-ed25519 MASTERKEYBLOB" not in remaining
    assert "# mention MASTERKEYBLOB" in remaining
    assert "ssh-ed25519 OTHERKEY" in remaining
    assert not revoke_paths.request.exists()
    assert not revoke_paths.endpoint.exists()
    assert json.loads(revoke_paths.state.read_text())["state"] == "revoked"


def test_expired_revocation_request_changes_nothing(revoke_paths):
    credential_revoke.queue_local_revoke("worker-one")
    request = json.loads(revoke_paths.request.read_text())
    request["requested_at"] = (
        datetime.now(timezone.utc) - timedelta(minutes=10)
    ).isoformat()
    revoke_paths.request.write_text(json.dumps(request) + "\n")
    revoke_paths.request.chmod(0o600)

    with pytest.raises(RuntimeError, match="expired"):
        credential_revoke.revoke()
    assert json.loads(revoke_paths.state.read_text())["state"] == "paired"
    assert revoke_paths.endpoint.exists()


def test_revocation_refuses_symlinked_authorized_keys(revoke_paths, tmp_path):
    target = tmp_path / "personal-keys"
    target.write_text("ssh-ed25519 PERSONAL keep\n")
    target.chmod(0o600)
    (revoke_paths.ssh_dir / "authorized_keys").symlink_to(target)
    credential_revoke.queue_local_revoke("worker-one")

    with pytest.raises(OSError):
        credential_revoke.revoke()
    assert target.read_text() == "ssh-ed25519 PERSONAL keep\n"
    assert json.loads(revoke_paths.state.read_text())["state"] == "paired"
