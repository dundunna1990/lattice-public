import os
from pathlib import Path
import stat
import uuid

import pytest

from lattice.file_access.keys import (
    FileKeyError,
    ensure_file_client_identity,
    ensure_file_host_identity,
    ensure_fleet_signing_identity,
    validate_ed25519_public_key,
)
from lattice.file_access.manifest import (
    FleetManifestError,
    canonical_manifest_bytes,
    normalize_manifest,
    require_newer_generation,
    sign_manifest,
    verify_manifest,
)


def _manifest(client, host, *, generation=1):
    return {
        "schema_version": 1,
        "fleet_id": str(uuid.uuid4()),
        "generation": generation,
        "members": [
            {
                "node_id": str(uuid.uuid4()),
                "hostname": "master-node",
                "role": "master",
                "main_user": "masteruser",
                "file_public_key": client.public_key_text,
                "file_host_public_key": host.public_key_text,
                "file_host_key_fingerprint": host.fingerprint,
                "file_key_generation": 1,
            }
        ],
        "revoked": [],
    }


def test_file_identities_are_distinct_and_idempotent(tmp_path):
    file_dir = tmp_path / "file-ssh"
    signing_dir = tmp_path / "signing"

    client = ensure_file_client_identity(file_dir)
    host = ensure_file_host_identity(file_dir)
    signing = ensure_fleet_signing_identity(signing_dir)

    assert client.public_key_text != host.public_key_text
    assert client.public_key_text != signing.public_key_text
    assert host.public_key_text != signing.public_key_text

    assert ensure_file_client_identity(file_dir) == client
    assert ensure_file_host_identity(file_dir) == host
    assert ensure_fleet_signing_identity(signing_dir) == signing


def test_key_permissions_are_restricted(tmp_path):
    pair = ensure_file_client_identity(tmp_path / "keys")

    assert stat.S_IMODE(pair.private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(pair.public_key.stat().st_mode) == 0o644
    assert stat.S_IMODE(pair.private_key.parent.stat().st_mode) == 0o700


def test_incomplete_keypair_is_refused(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir()

    private = directory / "client_ed25519"
    private.write_text("not a real key")

    with pytest.raises(FileKeyError, match="Incomplete keypair"):
        ensure_file_client_identity(directory)


def test_public_key_validation_rejects_wrong_algorithm():
    with pytest.raises(FileKeyError):
        validate_ed25519_public_key(
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"
        )


def test_manifest_is_canonical(tmp_path):
    client = ensure_file_client_identity(tmp_path / "client")
    host = ensure_file_host_identity(tmp_path / "host")

    manifest = _manifest(client, host)

    first = canonical_manifest_bytes(manifest)

    reordered = {
        "revoked": manifest["revoked"],
        "members": manifest["members"],
        "generation": manifest["generation"],
        "fleet_id": manifest["fleet_id"],
        "schema_version": manifest["schema_version"],
    }

    second = canonical_manifest_bytes(reordered)

    assert first == second


def test_signed_manifest_verifies_and_tampering_fails(tmp_path):
    client = ensure_file_client_identity(tmp_path / "client")
    host = ensure_file_host_identity(tmp_path / "host")
    signing = ensure_fleet_signing_identity(tmp_path / "signing")

    manifest = _manifest(client, host)
    signature = sign_manifest(manifest, signing.private_key)

    assert verify_manifest(
        manifest,
        signature,
        signing.public_key_text,
    )

    tampered = normalize_manifest(manifest)
    tampered["members"][0]["hostname"] = "evil-replacement"

    assert not verify_manifest(
        tampered,
        signature,
        signing.public_key_text,
    )


def test_wrong_signing_key_is_rejected(tmp_path):
    client = ensure_file_client_identity(tmp_path / "client")
    host = ensure_file_host_identity(tmp_path / "host")
    signing = ensure_fleet_signing_identity(tmp_path / "signing")
    wrong = ensure_fleet_signing_identity(tmp_path / "wrong")

    manifest = _manifest(client, host)
    signature = sign_manifest(manifest, signing.private_key)

    assert not verify_manifest(
        manifest,
        signature,
        wrong.public_key_text,
    )


def test_manifest_rejects_active_and_revoked_same_node(tmp_path):
    client = ensure_file_client_identity(tmp_path / "client")
    host = ensure_file_host_identity(tmp_path / "host")

    manifest = _manifest(client, host)
    node_id = manifest["members"][0]["node_id"]
    manifest["revoked"] = [node_id]

    with pytest.raises(FleetManifestError, match="active and revoked"):
        normalize_manifest(manifest)


def test_generation_must_move_forward(tmp_path):
    client = ensure_file_client_identity(tmp_path / "client")
    host = ensure_file_host_identity(tmp_path / "host")

    manifest = _manifest(client, host, generation=4)

    normalized = require_newer_generation(3, manifest)
    assert normalized["generation"] == 4

    with pytest.raises(FleetManifestError, match="not newer"):
        require_newer_generation(4, manifest)

    with pytest.raises(FleetManifestError, match="not newer"):
        require_newer_generation(5, manifest)


def test_duplicate_member_is_rejected(tmp_path):
    client = ensure_file_client_identity(tmp_path / "client")
    host = ensure_file_host_identity(tmp_path / "host")

    manifest = _manifest(client, host)
    manifest["members"].append(dict(manifest["members"][0]))

    with pytest.raises(FleetManifestError, match="duplicate node"):
        normalize_manifest(manifest)


def test_manifest_rejects_host_fingerprint_from_different_key(
    tmp_path,
):
    client = ensure_file_client_identity(
        tmp_path / "client-fingerprint-test"
    )
    host = ensure_file_host_identity(
        tmp_path / "host-fingerprint-test"
    )
    wrong_host = ensure_file_host_identity(
        tmp_path / "wrong-host-fingerprint-test"
    )

    manifest = _manifest(client, host)

    manifest["members"][0][
        "file_host_key_fingerprint"
    ] = wrong_host.fingerprint

    with pytest.raises(
        FleetManifestError,
        match="does not match its host key",
    ):
        normalize_manifest(manifest)
