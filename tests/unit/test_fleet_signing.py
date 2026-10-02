import copy
import uuid

import pytest

from lattice.file_access.keys import (
    _ensure_keypair,
    ensure_file_client_identity,
    ensure_file_host_identity,
    ensure_fleet_signing_identity,
)
from lattice.file_access.manifest import (
    normalize_manifest,
    sign_manifest,
    verify_manifest,
)
from lattice.file_access import fleet_signing
from lattice.shell_access.keys import (
    ensure_shell_client_identity,
    ensure_shell_host_identity,
)


def _member(
    tmp_path,
    prefix,
    node_id,
    hostname,
    role,
):
    file_dir = tmp_path / f"{prefix}-file"
    shell_dir = tmp_path / f"{prefix}-shell"

    file_client = ensure_file_client_identity(
        file_dir
    )
    file_host = ensure_file_host_identity(
        file_dir
    )
    shell_client = ensure_shell_client_identity(
        shell_dir
    )
    shell_host = ensure_shell_host_identity(
        shell_dir
    )

    return {
        "node_id": node_id,
        "hostname": hostname,
        "role": role,
        "main_user": "masteruser",
        "file_public_key":
            file_client.public_key_text,
        "file_host_public_key":
            file_host.public_key_text,
        "file_host_key_fingerprint":
            file_host.fingerprint,
        "file_key_generation": 1,
        "shell_public_key":
            shell_client.public_key_text,
        "shell_host_public_key":
            shell_host.public_key_text,
        "shell_host_key_fingerprint":
            shell_host.fingerprint,
        "shell_key_generation": 1,
    }


def _current_manifest(tmp_path):
    master_id = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())

    manifest = normalize_manifest({
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": 5,
        "members": [
            _member(
                tmp_path,
                "master",
                master_id,
                "master-node",
                "master",
            ),
            _member(
                tmp_path,
                "worker",
                worker_id,
                "worker-node",
                "worker",
            ),
        ],
        "revoked": [],
    })

    return manifest, master_id, worker_id


def _file_overlap(
    tmp_path,
    current,
    worker_id,
):
    candidate = copy.deepcopy(current)
    candidate["generation"] += 1

    target = next(
        item
        for item in candidate["members"]
        if item["node_id"] == worker_id
    )

    next_client = _ensure_keypair(
        tmp_path / "file-next",
        "client",
        "file-next-client",
    )
    next_host = _ensure_keypair(
        tmp_path / "file-next",
        "host",
        "file-next-host",
    )

    target.update({
        "file_next_public_key":
            next_client.public_key_text,
        "file_next_host_public_key":
            next_host.public_key_text,
        "file_next_host_key_fingerprint":
            next_host.fingerprint,
        "file_next_key_generation": 2,
    })

    return normalize_manifest(candidate)


def _shell_overlap(
    tmp_path,
    current,
    worker_id,
):
    candidate = copy.deepcopy(current)
    candidate["generation"] += 1

    target = next(
        item
        for item in candidate["members"]
        if item["node_id"] == worker_id
    )

    next_client = _ensure_keypair(
        tmp_path / "shell-next",
        "client",
        "shell-next-client",
    )
    next_host = _ensure_keypair(
        tmp_path / "shell-next",
        "host",
        "shell-next-host",
    )

    target.update({
        "shell_next_public_key":
            next_client.public_key_text,
        "shell_next_host_public_key":
            next_host.public_key_text,
        "shell_next_host_key_fingerprint":
            next_host.fingerprint,
        "shell_next_key_generation": 2,
    })

    return normalize_manifest(candidate)


def test_file_overlap_allows_only_target_next_identity(
    tmp_path,
):
    current, _master, worker = (
        _current_manifest(tmp_path)
    )
    overlap = _file_overlap(
        tmp_path,
        current,
        worker,
    )

    assert (
        fleet_signing.validate_rotation_transition(
            "file-overlap",
            worker,
            current,
            overlap,
        )
        == overlap
    )

    tampered = copy.deepcopy(overlap)
    master = next(
        item
        for item in tampered["members"]
        if item["node_id"] != worker
    )
    master["hostname"] = "master-alt"

    with pytest.raises(
        fleet_signing.FleetSigningError,
        match="another fleet member",
    ):
        fleet_signing.validate_rotation_transition(
            "file-overlap",
            worker,
            current,
            tampered,
        )


def test_file_finalize_only_promotes_staged_identity(
    tmp_path,
):
    current, _master, worker = (
        _current_manifest(tmp_path)
    )
    overlap = _file_overlap(
        tmp_path,
        current,
        worker,
    )

    final = copy.deepcopy(overlap)
    final["generation"] += 1

    target = next(
        item
        for item in final["members"]
        if item["node_id"] == worker
    )

    target["file_public_key"] = target.pop(
        "file_next_public_key"
    )
    target["file_host_public_key"] = target.pop(
        "file_next_host_public_key"
    )
    target["file_host_key_fingerprint"] = (
        target.pop(
            "file_next_host_key_fingerprint"
        )
    )
    target["file_key_generation"] = target.pop(
        "file_next_key_generation"
    )

    final = normalize_manifest(final)

    assert (
        fleet_signing.validate_rotation_transition(
            "file-finalize",
            worker,
            overlap,
            final,
        )
        == final
    )


def test_shell_overlap_uses_same_narrow_policy(
    tmp_path,
):
    current, _master, worker = (
        _current_manifest(tmp_path)
    )
    overlap = _shell_overlap(
        tmp_path,
        current,
        worker,
    )

    assert (
        fleet_signing.validate_rotation_transition(
            "shell-overlap",
            worker,
            current,
            overlap,
        )
        == overlap
    )


def test_runtime_client_verifies_signer_response(
    tmp_path,
    monkeypatch,
):
    current, _master, worker = (
        _current_manifest(tmp_path)
    )

    signing = ensure_fleet_signing_identity(
        tmp_path / "signing"
    )
    signature = sign_manifest(
        current,
        signing.private_key,
    )

    seen = {}

    monkeypatch.delenv(
        "LATTICE_FLEET_SIGNING_DIR",
        raising=False,
    )

    def fake_request(request):
        seen.update(request)
        return signature

    monkeypatch.setattr(
        fleet_signing,
        "_request_signer",
        fake_request,
    )

    returned = (
        fleet_signing.sign_rotation_manifest(
            "file-overlap",
            worker,
            current,
            signing.public_key_text,
        )
    )

    assert returned == signature
    assert seen["operation"] == "file-overlap"
    assert seen["target_node_id"] == worker
    assert verify_manifest(
        current,
        returned,
        signing.public_key_text,
    )


def test_runtime_client_rejects_invalid_signature(
    tmp_path,
    monkeypatch,
):
    current, _master, worker = (
        _current_manifest(tmp_path)
    )

    signing = ensure_fleet_signing_identity(
        tmp_path / "signing"
    )

    monkeypatch.delenv(
        "LATTICE_FLEET_SIGNING_DIR",
        raising=False,
    )

    monkeypatch.setattr(
        fleet_signing,
        "_request_signer",
        lambda _request: "not-a-signature",
    )

    with pytest.raises(
        fleet_signing.FleetSigningError,
        match="invalid signature",
    ):
        fleet_signing.sign_rotation_manifest(
            "file-overlap",
            worker,
            current,
            signing.public_key_text,
        )


def test_systemd_signer_is_root_isolated():
    master = open(
        "deploy/systemd/lattice-master.service",
        encoding="utf-8",
    ).read()

    socket_unit = open(
        "deploy/systemd/lattice-fleet-sign.socket",
        encoding="utf-8",
    ).read()

    service_unit = open(
        "deploy/systemd/lattice-fleet-sign@.service",
        encoding="utf-8",
    ).read()

    assert (
        "Requires=lattice-init.service "
        "lattice-fleet-sign.socket"
        in master
    )

    # Master daemon stays unprivileged/hardened.
    assert "User=lattice" in master
    assert "NoNewPrivileges=yes" in master

    # Only the dedicated socket can reach the root signer.
    assert "SocketGroup=lattice" in socket_unit
    assert "SocketMode=0660" in socket_unit
    assert "Accept=yes" in socket_unit

    # Signing request itself runs root-isolated.
    assert "User=root" in service_unit
    assert "StandardInput=socket" in service_unit
    assert "StandardOutput=socket" in service_unit
    assert "PrivateNetwork=yes" in service_unit
