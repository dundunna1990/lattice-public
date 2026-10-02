import json
import uuid

import pytest

from lattice.file_access.keys import (
    ensure_file_client_identity,
    ensure_file_host_identity,
    ensure_fleet_signing_identity,
)
from lattice.file_access.manifest import (
    normalize_manifest,
    sign_manifest,
)
from lattice.file_access.transport_queue import (
    FileTransportQueueError,
    queue_transport_reconcile,
)


def _signed(tmp_path, generation):
    client = ensure_file_client_identity(
        tmp_path / f"client-{generation}"
    )
    host = ensure_file_host_identity(
        tmp_path / f"host-{generation}"
    )
    signing = ensure_fleet_signing_identity(
        tmp_path / "signing"
    )

    manifest = normalize_manifest(
        {
            "schema_version": 1,
            "fleet_id":
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "generation": generation,
            "members": [
                {
                    "node_id":
                        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    "hostname": "master-node",
                    "role": "master",
                    "main_user": "masteruser",
                    "file_public_key":
                        client.public_key_text,
                    "file_host_public_key":
                        host.public_key_text,
                    "file_host_key_fingerprint":
                        host.fingerprint,
                    "file_key_generation": 1,
                }
            ],
            "revoked": [],
        }
    )

    return (
        manifest,
        sign_manifest(
            manifest,
            signing.private_key,
        ),
    )


def test_queue_writes_signed_transport_request(
    tmp_path,
    monkeypatch,
):
    request = tmp_path / "request.json"

    monkeypatch.setenv(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH",
        str(request),
    )

    manifest, signature = _signed(
        tmp_path,
        1,
    )

    assert queue_transport_reconcile(
        manifest,
        signature,
    ) is True

    payload = json.loads(
        request.read_text()
    )

    assert payload["manifest"]["generation"] == 1
    assert payload["signature"] == signature


def test_queue_is_idempotent(
    tmp_path,
    monkeypatch,
):
    request = tmp_path / "request.json"

    monkeypatch.setenv(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH",
        str(request),
    )

    manifest, signature = _signed(
        tmp_path,
        1,
    )

    assert queue_transport_reconcile(
        manifest,
        signature,
    )

    assert not queue_transport_reconcile(
        manifest,
        signature,
    )


def test_queue_never_replaces_newer_generation(
    tmp_path,
    monkeypatch,
):
    request = tmp_path / "request.json"

    monkeypatch.setenv(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH",
        str(request),
    )

    newer, newer_sig = _signed(
        tmp_path,
        3,
    )
    older, older_sig = _signed(
        tmp_path,
        2,
    )

    assert queue_transport_reconcile(
        newer,
        newer_sig,
    )

    assert not queue_transport_reconcile(
        older,
        older_sig,
    )

    payload = json.loads(
        request.read_text()
    )

    assert payload["manifest"]["generation"] == 3


def test_queue_refuses_same_generation_conflict(
    tmp_path,
    monkeypatch,
):
    request = tmp_path / "request.json"

    monkeypatch.setenv(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH",
        str(request),
    )

    first, first_sig = _signed(
        tmp_path / "first",
        2,
    )
    second, second_sig = _signed(
        tmp_path / "second",
        2,
    )

    queue_transport_reconcile(
        first,
        first_sig,
    )

    with pytest.raises(
        FileTransportQueueError,
        match="Conflicting",
    ):
        queue_transport_reconcile(
            second,
            second_sig,
        )


def test_queue_refuses_symlink_request(
    tmp_path,
    monkeypatch,
):
    target = tmp_path / "target.json"
    target.write_text("{}")

    request = tmp_path / "request.json"
    request.symlink_to(target)

    monkeypatch.setenv(
        "LATTICE_FILE_TRANSPORT_REQUEST_PATH",
        str(request),
    )

    manifest, signature = _signed(
        tmp_path,
        1,
    )

    with pytest.raises(
        FileTransportQueueError,
    ):
        queue_transport_reconcile(
            manifest,
            signature,
        )

    assert target.read_text() == "{}"
