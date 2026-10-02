"""
Async master HTTP client for communicating with workers.

Provides:
- pinned worker TLS certificate verification
- per-worker bearer authentication
- persistent HTTP connections
- retry/backoff for transient failures
- idempotency keys for mutating requests

All network waits are native asyncio/httpx.AsyncClient operations so a slow
or unreachable worker cannot block the master's asyncio event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import ssl
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from lattice.core.config import load_config
from lattice.core.pki import tls_hostname
from lattice.core.worker_auth import read_token_file


logger = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT = 2
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_IDLE_TIMEOUT = 60
DEFAULT_MAX_CONNECTION_LIFETIME = 300
DEFAULT_MAX_RETRIES = 3
DEFAULT_INITIAL_BACKOFF_MS = 100
DEFAULT_MAX_BACKOFF_MS = 2000


class LatticeHTTPClient:
    """Persistent asynchronous client for one paired worker."""

    def __init__(
        self,
        worker_hostname: str,
        token_path: Optional[Path] = None,
    ):
        self.hostname = worker_hostname

        if token_path is None:
            token_path = (
                Path("/etc/lattice/tokens")
                / f"{worker_hostname}.token"
            )
        self.token_path = Path(token_path)

        certificate_dir = Path(
            os.environ.get(
                "LATTICE_WORKER_CERT_DIR",
                "/etc/lattice/worker-certs",
            )
        )
        self.worker_certificate = (
            certificate_dir / f"{worker_hostname}.crt"
        )

        config = load_config()
        try:
            wf = config.wire_format
            self.connect_timeout = getattr(
                wf,
                "connect_timeout_seconds",
                DEFAULT_CONNECT_TIMEOUT,
            )
            self.request_timeout = getattr(
                wf,
                "request_timeout_seconds",
                DEFAULT_REQUEST_TIMEOUT,
            )
            self.idle_timeout = getattr(
                wf,
                "idle_timeout_seconds",
                DEFAULT_IDLE_TIMEOUT,
            )
            self.max_connection_lifetime = getattr(
                wf,
                "max_connection_lifetime_seconds",
                DEFAULT_MAX_CONNECTION_LIFETIME,
            )
            self.max_retries = getattr(
                wf,
                "max_retry_attempts",
                DEFAULT_MAX_RETRIES,
            )
            self.initial_backoff_ms = getattr(
                wf,
                "retry_initial_backoff_ms",
                DEFAULT_INITIAL_BACKOFF_MS,
            )
            self.max_backoff_ms = getattr(
                wf,
                "retry_max_backoff_ms",
                DEFAULT_MAX_BACKOFF_MS,
            )
        except AttributeError:
            self.connect_timeout = DEFAULT_CONNECT_TIMEOUT
            self.request_timeout = DEFAULT_REQUEST_TIMEOUT
            self.idle_timeout = DEFAULT_IDLE_TIMEOUT
            self.max_connection_lifetime = (
                DEFAULT_MAX_CONNECTION_LIFETIME
            )
            self.max_retries = DEFAULT_MAX_RETRIES
            self.initial_backoff_ms = DEFAULT_INITIAL_BACKOFF_MS
            self.max_backoff_ms = DEFAULT_MAX_BACKOFF_MS

        self._client: httpx.AsyncClient | None = None

    def _read_token(self) -> str:
        try:
            return read_token_file(self.token_path)
        except (FileNotFoundError, ValueError):
            raise RuntimeError(
                f"Token file {self.token_path} not found"
            )

    def _secure_url(self, url: str) -> str:
        """Require pinned TLS identity for every paired-worker request."""
        if not self.worker_certificate.is_file():
            raise RuntimeError(
                f"Pinned TLS certificate for worker {self.hostname} is missing; "
                "secure worker communication requires repair"
            )

        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise RuntimeError(
                f"Unsupported worker URL scheme {parsed.scheme!r}; secure HTTPS is required"
            )

        host = tls_hostname(self.hostname)
        netloc = (
            f"{host}:{parsed.port}"
            if parsed.port
            else host
        )

        return urlunsplit(
            (
                "https",
                netloc,
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            timeout = httpx.Timeout(
                self.request_timeout,
                connect=self.connect_timeout,
            )
            self._client = httpx.AsyncClient(
                timeout=timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=1,
                    keepalive_expiry=self.idle_timeout,
                ),
                verify=ssl.create_default_context(
                    cafile=str(self.worker_certificate)
                ),
            )
        return self._client

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        url = self._secure_url(url)

        # Generate one idempotency key for the logical operation.
        # Retries must reuse the same key.
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = (
            f"Bearer {self._read_token()}"
        )

        if method.upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            headers["Idempotency-Key"] = str(uuid.uuid4())

        backoff_ms = self.initial_backoff_ms

        for attempt in range(self.max_retries):
            try:
                response = await self._ensure_client().request(
                    method,
                    url,
                    headers=headers,
                    **kwargs,
                )

                if (
                    400 <= response.status_code < 500
                    and response.status_code
                    not in (408, 425, 429)
                ):
                    return response

                response.raise_for_status()
                return response

            except (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.NetworkError,
            ):
                if attempt == self.max_retries - 1:
                    raise

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500:
                    raise

                if attempt == self.max_retries - 1:
                    raise

                logger.warning(
                    "HTTP request attempt %s/%s failed "
                    "with status %s",
                    attempt + 1,
                    self.max_retries,
                    exc.response.status_code,
                )

            jitter = random.uniform(-0.25, 0.25)
            sleep_ms = backoff_ms * (1 + jitter)

            await asyncio.sleep(
                max(0.0, sleep_ms / 1000)
            )

            backoff_ms = min(
                backoff_ms * 2,
                self.max_backoff_ms,
            )

        raise RuntimeError("Max retries exceeded")

    async def get(
        self,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        return await self._request_with_retry(
            "GET",
            url,
            **kwargs,
        )

    async def post(
        self,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        return await self._request_with_retry(
            "POST",
            url,
            **kwargs,
        )

    async def put(
        self,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        return await self._request_with_retry(
            "PUT",
            url,
            **kwargs,
        )

    async def delete(
        self,
        url: str,
        **kwargs,
    ) -> httpx.Response:
        return await self._request_with_retry(
            "DELETE",
            url,
            **kwargs,
        )

    async def aclose(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    def close(self) -> None:
        """Compatibility shutdown hook for synchronous daemon cleanup."""
        if self._client is None:
            return

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.aclose())
            return

        loop.create_task(self.aclose())
