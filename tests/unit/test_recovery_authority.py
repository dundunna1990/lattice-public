"""Recovery SSH authority is root-owned and derived access is repairable."""
import base64
import json
import os
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest


def _public_key(fill: bytes = b"r") -> str:
    wire = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + fill * 32
    return "ssh-ed25519 " + base64.b64encode(wire).decode("ascii")


def _authority(namespace, *, home: Path):
    public = _public_key()
    _, fingerprint = namespace["_validate_key_blob"](public.split()[1])
    authority = {
        "version": 1,
        "pairing_id": "Nukx_DHCN_6CH_IUL7t7FhSx4d2agBvf",
        "worker_hostname": "worker-node",
        "ssh_user": "workeruser",
        "master_hostname": "master-node",
        "master_ip": "10.77.0.200",
        "master_key_blob": public.split()[1],
        "master_public_key": public,
        "master_key_fingerprint": fingerprint,
        "approved_at": "2026-08-30T00:00:00+00:00",
    }
    account = SimpleNamespace(
        pw_name="workeruser", pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(home)
    )
    return authority, account, public


def test_repair_recreates_missing_ssh_and_preserves_unrelated_keys(tmp_path):
    namespace = runpy.run_path("deploy/lattice-recovery-auth-exec")
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    authority, account, public = _authority(namespace, home=home)

    namespace["_repair_authorized_keys"](authority, account, public)
    authorized = home / ".ssh" / "authorized_keys"
    first = authorized.read_text()
    assert 'command="/opt/lattice/bin/lattice-ssh-command"' in first
    assert 'from="10.77.0.200/32"' in first
    assert authorized.stat().st_mode & 0o777 == 0o600

    personal = "ssh-ed25519 " + _public_key(b"p").split()[1] + " personal"
    authorized.write_text(personal + "\n" + first)
    namespace["_repair_authorized_keys"](authority, account, public)
    repaired = authorized.read_text()
    assert personal in repaired
    assert repaired.count('command="/opt/lattice/bin/lattice-ssh-command"') == 1


def test_state_must_match_root_authority(tmp_path):
    namespace = runpy.run_path("deploy/lattice-recovery-auth-exec")
    authority, _, _ = _authority(namespace, home=tmp_path)
    state = {
        "state": "paired",
        "pairing_id": authority["pairing_id"],
        "hostname": authority["worker_hostname"],
        "ssh_user": authority["ssh_user"],
        "master_ip": "10.77.0.99",
        "master_key_blob": authority["master_key_blob"],
    }
    with pytest.raises(RuntimeError, match="disagrees"):
        namespace["_state_matches_authority"](state, authority)


def test_installer_and_revocation_wire_root_recovery_authority():
    installer = Path("deploy/install.sh").read_text()
    pairing = Path("deploy/lattice-pairing-exec").read_text()
    revoke = Path("lattice/credential_revoke.py").read_text()
    assert "lattice-recovery-auth-exec" in installer
    assert '"$INSTALL_ROOT/bin/lattice-recovery-auth-exec" --repair' in installer
    assert "RECOVERY_AUTHORITY_PATH" in pairing
    assert '"master_key_fingerprint"' in pairing
    assert "RECOVERY_AUTHORITY" in revoke
    assert "MASTER_CA, RECOVERY_AUTHORITY" in revoke
