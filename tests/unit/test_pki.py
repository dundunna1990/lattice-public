"""Focused tests for stable TLS identities across address changes."""
import subprocess

import pytest

from lattice.core.pki import (
    PKIError,
    ensure_master_identity,
    ensure_worker_identity,
    tls_hostname,
    tls_server_options,
)


def test_worker_certificate_covers_its_stable_mdns_hostname(tmp_path, monkeypatch):
    monkeypatch.setenv("LATTICE_PKI_DIR", str(tmp_path / "pki"))

    identity = ensure_worker_identity("worker-node", ip="10.77.0.103")
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(identity["cert"]),
            "-noout",
            "-checkhost",
            "worker-node.local",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert tls_hostname("worker-node") == "worker-node.local"
    assert tls_hostname("worker-node.local") == "worker-node.local"
    assert result.returncode == 0, result.stderr or result.stdout


def test_partial_ca_identity_refuses_automatic_rotation(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"
    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki),
    )

    identity = ensure_master_identity(
        "master-one",
        "127.0.0.1",
    )

    original_key = (
        pki / "ca.key"
    ).read_bytes()

    identity["ca"].unlink()

    with pytest.raises(
        PKIError,
        match="CA identity is incomplete",
    ):
        ensure_master_identity(
            "master-one",
            "127.0.0.1",
        )

    assert (
        pki / "ca.key"
    ).read_bytes() == original_key


def test_corrupt_ca_identity_fails_closed(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"
    pki.mkdir()

    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki),
    )

    (pki / "ca.key").write_text(
        "broken key"
    )
    (pki / "ca.crt").write_text(
        "broken cert"
    )

    with pytest.raises(
        PKIError,
        match="CA identity is invalid",
    ):
        ensure_master_identity(
            "master-one",
            "127.0.0.1",
        )


def test_corrupt_master_leaf_is_reissued_from_same_ca(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"

    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki),
    )

    identity = ensure_master_identity(
        "master-one",
        "127.0.0.1",
    )

    original_ca_key = (
        pki / "ca.key"
    ).read_bytes()

    identity["cert"].write_text(
        "broken master cert"
    )

    repaired = ensure_master_identity(
        "master-one",
        "127.0.0.1",
    )

    assert (
        pki / "ca.key"
    ).read_bytes() == original_ca_key

    result = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(repaired["ca"]),
            str(repaired["cert"]),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0


def test_tls_options_reject_corrupt_existing_identity(
    tmp_path,
    monkeypatch,
):
    pki = tmp_path / "pki"
    pki.mkdir()

    monkeypatch.setenv(
        "LATTICE_PKI_DIR",
        str(pki),
    )

    (pki / "worker.key").write_text(
        "broken"
    )
    (pki / "worker.crt").write_text(
        "broken"
    )

    with pytest.raises(
        PKIError,
        match="invalid or expired",
    ):
        tls_server_options("worker")
