"""Client for the local read-only Lattice operator interface."""
from __future__ import annotations

import json
import os
import socket


DEFAULT_OPERATOR_SOCKET = "/run/lattice-operator/operator.sock"


class OperatorClientError(RuntimeError):
    pass


def request(command: str, params: dict | None = None, *, timeout: float = 5.0):
    path = os.environ.get("LATTICE_OPERATOR_SOCKET", DEFAULT_OPERATOR_SOCKET)
    payload = {"command": command, "params": params or {}}
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) > 8192:
        raise OperatorClientError("Operator request is too large")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(path)
        client.sendall(raw)
        chunks = []
        total = 0
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 2 * 1024 * 1024:
                raise OperatorClientError("Operator response is unexpectedly large")
            chunks.append(chunk)
    except (OSError, socket.timeout) as exc:
        raise OperatorClientError(f"Could not contact the local Lattice operator service: {exc}") from exc
    finally:
        client.close()
    try:
        response = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorClientError("Operator service returned an invalid response") from exc
    if not isinstance(response, dict) or response.get("ok") is not True:
        detail = response.get("error") if isinstance(response, dict) else None
        raise OperatorClientError(str(detail or "Operator request failed"))
    return response.get("data")
