from datetime import datetime, timezone
import subprocess

import pytest

from lattice.ip_change.assignment_auth import (
    NetworkAssignmentAuthError,
    sign_network_assignment,
    verify_network_assignment,
)


def _payload():
    return {
        "assignment_id": "11111111-1111-4111-8111-111111111111",
        "worker_hostname": "worker-node",
        "worker_node_id": "22222222-2222-4222-8222-222222222222",
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "address": "10.77.0.202",
        "prefix": 24,
        "gateway": "10.77.0.254",
        "dns": ["10.77.0.254"],
    }


def test_exact_network_assignment_is_signed_and_verified(tmp_path):
    key = tmp_path / "fleet_signing_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public = key.with_suffix(".pub").read_text().strip()
    signed = sign_network_assignment(_payload(), private_key=key)
    verified = verify_network_assignment(signed, signed["signature"], public)
    assert verified["address"] == "10.77.0.202"
    assert verified["worker_hostname"] == "worker-node"


def test_tampered_exact_network_assignment_is_rejected(tmp_path):
    key = tmp_path / "fleet_signing_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
        check=True,
    )
    public = key.with_suffix(".pub").read_text().strip()
    signed = sign_network_assignment(_payload(), private_key=key)
    signed["address"] = "10.77.0.203"
    with pytest.raises(NetworkAssignmentAuthError, match="did not verify"):
        verify_network_assignment(signed, signed["signature"], public)


def test_network_assignment_rejects_unexpected_unsigned_fields():
    payload = _payload()
    payload["command"] = "anything"
    with pytest.raises(NetworkAssignmentAuthError, match="unexpected fields"):
        sign_network_assignment(payload, private_key="/does/not/matter")
