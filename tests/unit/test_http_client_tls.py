from unittest.mock import AsyncMock, MagicMock, patch

from lattice.core.http_client import LatticeHTTPClient


async def test_client_uses_pinned_worker_certificate_and_tls_hostname(
    tmp_path,
    monkeypatch,
):
    token_path = tmp_path / "worker.token"
    token_path.write_text("t" * 48 + "\n")
    token_path.chmod(0o600)

    cert_dir = tmp_path / "worker-certs"
    cert_dir.mkdir()
    certificate = cert_dir / "worker-node.crt"
    certificate.write_text("test certificate")

    monkeypatch.setenv(
        "LATTICE_WORKER_CERT_DIR",
        str(cert_dir),
    )

    response = MagicMock()
    response.status_code = 200
    response.raise_for_status.return_value = None

    request = AsyncMock(return_value=response)
    verify_context = MagicMock(name="verify_context")

    with patch(
        "lattice.core.http_client.ssl.create_default_context",
        return_value=verify_context,
    ) as create_context, patch(
        "lattice.core.http_client.httpx.AsyncClient"
    ) as client_factory:
        client_factory.return_value.request = request
        client_factory.return_value.aclose = AsyncMock()

        client = LatticeHTTPClient(
            "worker-node",
            token_path=token_path,
        )

        result = await client.get(
            "http://10.77.0.201:9999/v1/health"
        )

        assert result is response

        client_factory.assert_called_once()

        create_context.assert_called_once_with(
            cafile=str(certificate)
        )

        assert (
            client_factory.call_args.kwargs["verify"]
            is verify_context
        )

        limits = client_factory.call_args.kwargs["limits"]
        assert limits.keepalive_expiry == client.idle_timeout

        requested_url = request.call_args.args[1]

        assert (
            requested_url
            == "https://worker-node.local:9999/v1/health"
        )

        assert (
            request.call_args.kwargs["headers"][
                "Authorization"
            ]
            == "Bearer " + ("t" * 48)
        )

        await client.aclose()


async def test_client_refuses_to_send_token_without_pinned_certificate(tmp_path, monkeypatch):
    token_path = tmp_path / "worker.token"
    token_path.write_text("t" * 48 + "\n")
    token_path.chmod(0o600)
    cert_dir = tmp_path / "worker-certs"
    cert_dir.mkdir()
    monkeypatch.setenv("LATTICE_WORKER_CERT_DIR", str(cert_dir))

    with patch("lattice.core.http_client.httpx.AsyncClient") as client_factory:
        client = LatticeHTTPClient("worker-node", token_path=token_path)
        import pytest
        with pytest.raises(RuntimeError, match="Pinned TLS certificate"):
            await client.get("http://10.77.0.201:9999/v1/health")
        client_factory.assert_not_called()


async def test_client_rejects_non_http_scheme_before_bearer_auth(tmp_path, monkeypatch):
    token_path = tmp_path / "worker.token"
    token_path.write_text("t" * 48 + "\n")
    token_path.chmod(0o600)
    cert_dir = tmp_path / "worker-certs"
    cert_dir.mkdir()
    (cert_dir / "worker-node.crt").write_text("test certificate")
    monkeypatch.setenv("LATTICE_WORKER_CERT_DIR", str(cert_dir))
    with patch("lattice.core.http_client.httpx.AsyncClient") as client_factory:
        client = LatticeHTTPClient("worker-node", token_path=token_path)
        import pytest
        with pytest.raises(RuntimeError, match="Unsupported worker URL scheme"):
            await client.get("ftp://worker-node/v1/health")
        client_factory.assert_not_called()
