from fastapi import FastAPI, HTTPException, Header, Depends, Request
import asyncio
import json
import logging

logger = logging.getLogger(__name__)
from pydantic import BaseModel, Field
from typing import Optional, List
import os
import socket
import hmac
import warnings
import subprocess
import uuid
from pathlib import Path
from lattice.core.worker_auth import read_token_file

from lattice.core.config import load_config
from lattice.healing.hard_no import is_autoheal_action_allowed
from lattice.onboarding import PairingError, confirm_worker_pairing, get_public_pairing_status
from lattice.ip_change.worker_assignment import StaticIPError, queue_network_assignment, read_assignment_result
from lattice.credential_revoke import queue_local_revoke
from lattice.file_access.sync import (
    FleetSyncError,
    apply_signed_manifest,
)
from lattice.worker.health import HealthChecker
from lattice.backup.manual import ManualBackupError, queue_manual_backup
from lattice.backup.query import (
    BackupQueryError, queue_backup_query, read_backup_query_result,
)
from lattice.backup.restore_request import (
    BackupRestoreRequestError,
    queue_restore_request,
    read_restore_result,
)

# Firewall rules are deliberately handled once in the privileged installation
# wizard. Normal worker runtime must never edit a firewall.
app = FastAPI(title="Lattice Worker API", version="1.0.0")

# Unique for the lifetime of this worker process. A real restart must produce
# a different value, allowing the master to distinguish "still healthy" from
# "the requested restart actually happened".
WORKER_INSTANCE_ID = uuid.uuid4().hex


def load_worker_token() -> str:
    """Read the worker's bearer token from the canonical path.
    Honors LATTICE_TOKEN_PATH env var for test isolation; falls back to
    /etc/lattice/tokens/{hostname}.token in production.
    """
    token_path = os.environ.get("LATTICE_TOKEN_PATH")
    if not token_path:
        hostname = socket.gethostname()
        token_path = f"/etc/lattice/tokens/{hostname}.token"
    try:
        return read_token_file(Path(token_path))
    except FileNotFoundError:
        raise RuntimeError(f"Token file {token_path} not found. Worker cannot start.")
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Token file {token_path} cannot be read safely: {exc}") from exc


async def verify_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=400, detail="Invalid auth scheme")
        expected_token = load_worker_token()
        if not hmac.compare_digest(token, expected_token):
            raise HTTPException(status_code=403, detail="Invalid bearer token")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Authorization header format")
    return token


class ActionRequest(BaseModel):
    action: str = Field(..., description="One of the allowed actions: restart, stop, reload, status")
    target: str = Field(..., description="Service or component name")


class PairingRequest(BaseModel):
    pairing_id: str = Field(..., min_length=16, max_length=128)
    code: str = Field(..., min_length=8, max_length=16)
    master_hostname: str = Field(..., min_length=1, max_length=63)
    master_ip: str = Field(..., min_length=1, max_length=45)
    master_public_key: str = Field(..., min_length=32, max_length=1024)
    fleet_id: str = Field(..., min_length=36, max_length=36)
    master_node_id: str = Field(..., min_length=36, max_length=36)
    master_file_public_key: str = Field(..., min_length=32, max_length=1024)
    master_file_host_public_key: str = Field(..., min_length=32, max_length=1024)
    master_file_host_key_fingerprint: str = Field(..., min_length=8, max_length=256)
    master_shell_public_key: str | None = Field(default=None, min_length=32, max_length=1024)
    master_shell_host_public_key: str | None = Field(default=None, min_length=32, max_length=1024)
    master_shell_host_key_fingerprint: str | None = Field(default=None, min_length=8, max_length=256)
    fleet_signing_public_key: str = Field(..., min_length=32, max_length=1024)
    worker_token: str = Field(..., min_length=32, max_length=512)
    master_ca_certificate: str = Field(default="", max_length=16384)
    master_api_port: int = Field(default=8080, ge=1, le=65535)


class BackupRunRequest(BaseModel):
    job_uuid: str = Field(..., min_length=36, max_length=36)
    full_speed: bool = False
    allow_large_first_backup: bool = False


class BackupRestoreRequest(BaseModel):
    operation: str = Field(..., pattern=r"^(stage|place|cancel)$")
    job_uuid: str | None = Field(default=None, max_length=36)
    snapshot_id: str | None = Field(default=None, max_length=128)
    selection: str | None = Field(default=None, max_length=4096)
    session_uuid: str | None = Field(default=None, max_length=36)
    choice: str | None = Field(default=None, pattern=r"^(keep_both|replace|elsewhere)$")
    elsewhere: str | None = Field(default=None, max_length=4096)


class BackupQueryRequest(BaseModel):
    job_uuid: str = Field(..., min_length=36, max_length=36)
    operation: str = Field(..., pattern=r"^(snapshots|directory|recovery_preflight)$")
    snapshot_id: str | None = Field(default=None, max_length=128)
    directory: str | None = Field(default=None, max_length=4096)


class FleetManifestRequest(BaseModel):
    manifest: dict
    signature: str = Field(..., min_length=32, max_length=16384)


class NetworkAssignmentRequest(BaseModel):
    assignment_id: str = Field(..., min_length=36, max_length=36)
    worker_hostname: str = Field(..., min_length=1, max_length=63)
    worker_node_id: str = Field(..., min_length=36, max_length=36)
    issued_at: str = Field(..., min_length=20, max_length=64)
    address: str = Field(..., min_length=7, max_length=15)
    prefix: int = Field(..., ge=1, le=30)
    gateway: str = Field(..., min_length=7, max_length=15)
    dns: List[str] = Field(default_factory=list, max_length=4)
    signature: str = Field(..., min_length=64, max_length=16384)


@app.get("/v1/health")
async def health_check():
    """Return only the overall live verdict; detailed evidence stays authenticated."""
    snapshot = await asyncio.to_thread(HealthChecker().current_snapshot)
    return {
        "status": snapshot["status"],
        "service": "lattice-worker",
        "instance_id": WORKER_INSTANCE_ID,
    }


@app.get("/v1/pairing/status")
async def pairing_status():
    """Expose only non-secret waiting information for local master discovery."""
    try:
        status = get_public_pairing_status()
    except PairingError as exc:
        logger.error(f"Could not read pairing status: {exc}")
        raise HTTPException(status_code=503, detail="Pairing state is unavailable")
    if status is None:
        raise HTTPException(status_code=404, detail="Worker is not waiting to be paired")
    return status


@app.post("/v1/pairing/confirm", status_code=202)
async def pairing_confirm(pairing: PairingRequest, request: Request):
    """Record a master request after it proves the worker's one-time code."""
    try:
        source_ip = request.client.host if request.client else "unknown"
        result = confirm_worker_pairing(**pairing.model_dump(), source_ip=source_ip)
    except PairingError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    if result["state"] == "awaiting_approval":
        return result
    return result


@app.get("/v1/fleet/identity", dependencies=[Depends(verify_token)])
async def fleet_identity():
    """Return permanent identity plus verified durable fleet-generation state."""
    from lattice.onboarding import get_paired_worker_identity, PairingError
    from lattice.file_access.sync import FleetSyncError, get_cached_signed_manifest

    try:
        payload = get_paired_worker_identity()
        cached = get_cached_signed_manifest()
        payload["fleet_generation"] = (
            int(cached[0]["generation"]) if cached is not None else 0
        )
        return payload
    except (PairingError, FleetSyncError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/v1/fleet/manifest", dependencies=[Depends(verify_token)])
async def fleet_manifest(request: FleetManifestRequest):
    """Verify, cache, and ACK one signed fleet generation."""
    try:
        result = apply_signed_manifest(request.manifest, request.signature)
    except FleetSyncError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return result


@app.post("/v1/network/assign", status_code=202, dependencies=[Depends(verify_token)])
async def network_assign(request: NetworkAssignmentRequest):
    """Accept the master's one-time automatic address assignment after pairing."""
    try:
        queue_network_assignment(request.model_dump())
    except StaticIPError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"status": "accepted", "message": "Worker will apply and verify its assigned address."}


@app.get("/v1/network/assignment-status", dependencies=[Depends(verify_token)])
async def network_assignment_status():
    """Return only the root network helper's completed or failed result."""
    try:
        result = read_assignment_result()
    except (OSError, ValueError, StaticIPError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result is None:
        return {"status": "pending"}
    return result


@app.post("/v1/pairing/revoke", status_code=202, dependencies=[Depends(verify_token)])
async def pairing_revoke():
    """Queue root-owned local credential deletion before the master forgets this worker."""
    try:
        queue_local_revoke(socket.gethostname())
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "accepted", "message": "Worker credentials will be revoked locally."}


@app.get("/v1/services", dependencies=[Depends(verify_token)])
async def list_services():
    """Return the same live service evidence used by worker health."""
    snapshot = await asyncio.to_thread(HealthChecker().current_snapshot)
    return {
        "worker_id": socket.gethostname(),
        "services": snapshot["services"],
    }


@app.get("/v1/verification", dependencies=[Depends(verify_token)])
async def live_verification():
    """Return bounded read-only evidence for fleet-wide verification."""
    from lattice.verification.node import VerificationError, collect_local_verification
    try:
        return await asyncio.to_thread(collect_local_verification, "worker")
    except VerificationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/v1/verification/clear", dependencies=[Depends(verify_token)])
async def clear_verified_local_state():
    """Ask the narrow root helper to clear only freshly proven stale state."""
    command = [
        "/usr/bin/sudo", "-n",
        "/opt/lattice/bin/lattice-verification-control", "clear-local",
    ]
    try:
        result = await asyncio.to_thread(
            subprocess.run, command, capture_output=True, text=True,
            timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HTTPException(status_code=503, detail=f"verification clear failed: {exc}") from exc
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail="verification clear returned invalid output") from exc
    if result.returncode != 0:
        raise HTTPException(
            status_code=409,
            detail=str(payload.get("error") or result.stderr or "verification clear was refused"),
        )
    return payload


@app.post("/v1/backups/restore", status_code=202, dependencies=[Depends(verify_token)])
async def backup_restore(request: BackupRestoreRequest):
    try:
        request_id = await asyncio.to_thread(
            queue_restore_request,
            request.operation,
            job_uuid=request.job_uuid,
            snapshot_id=request.snapshot_id,
            selection=request.selection,
            session_uuid=request.session_uuid,
            choice=request.choice,
            elsewhere=request.elsewhere,
        )
    except BackupRestoreRequestError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "accepted", "request_id": request_id}


@app.get("/v1/backups/restore-result/{request_id}", dependencies=[Depends(verify_token)])
async def backup_restore_result(request_id: str):
    try:
        result = await asyncio.to_thread(read_restore_result, request_id)
    except BackupRestoreRequestError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        return {"status": "pending", "request_id": request_id}
    return result


@app.post("/v1/backups/query", status_code=202, dependencies=[Depends(verify_token)])
async def backup_query(request: BackupQueryRequest):
    try:
        request_id = await asyncio.to_thread(
            queue_backup_query,
            request.job_uuid,
            request.operation,
            snapshot_id=request.snapshot_id,
            directory=request.directory,
        )
    except BackupQueryError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"status": "accepted", "request_id": request_id}


@app.get("/v1/backups/query-result/{request_id}", dependencies=[Depends(verify_token)])
async def backup_query_result(request_id: str):
    try:
        result = await asyncio.to_thread(read_backup_query_result, request_id)
    except BackupQueryError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        return {"status": "pending", "request_id": request_id}
    return result


@app.post("/v1/backups/run", status_code=202, dependencies=[Depends(verify_token)])
async def backup_run_now(request: BackupRunRequest):
    """Queue one source-owned backup job; root revalidates before execution."""
    try:
        queued = await asyncio.to_thread(
            queue_manual_backup,
            request.job_uuid,
            full_speed=request.full_speed,
            allow_large_first_backup=request.allow_large_first_backup,
        )
    except ManualBackupError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {
        "status": "accepted" if queued else "already_pending",
        "job_uuid": request.job_uuid,
        "message": "Backup has been queued on this source computer.",
    }


@app.post("/v1/actions", status_code=202, dependencies=[Depends(verify_token)])
async def execute_action(req: ActionRequest):
    """Accept exactly one safe, restricted recovery action.

    The worker daemon never runs systemctl directly. It may only launch the
    root-owned helper for ``restart lattice-worker.service``. The helper and
    its sudo rule cannot be repurposed to touch SSH, firewall, networking, or
    arbitrary services.
    """
    import re
    if req.action != "restart":
        raise HTTPException(
            status_code=400,
            detail="Only restart of the local Lattice worker service is permitted.",
        )

    if not req.target or not req.target.strip():
        raise HTTPException(status_code=400, detail="Target must not be empty")
    if len(req.target) > 128:
        raise HTTPException(status_code=400, detail="Target too long (max 128 characters)")
    if not re.match(r"^[A-Za-z0-9._@\-]+$", req.target):
        raise HTTPException(
            status_code=400,
            detail=f"Target '{req.target}' contains invalid characters",
        )

    normalized_target = req.target[:-8] if req.target.endswith(".service") else req.target
    if normalized_target != "lattice-worker" or not is_autoheal_action_allowed(req.action, normalized_target):
        raise HTTPException(
            status_code=403,
            detail="Only restart of lattice-worker.service is allowed by the auto-heal safety policy",
        )

    try:
        if load_config().daemon.dry_run:
            raise HTTPException(
                status_code=409,
                detail="Dry run is enabled; no action was executed",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Could not read dry-run setting; blocking action: {exc}")
        raise HTTPException(status_code=503, detail="Could not verify dry-run safety setting")

    cmd = ["sudo", "-n", "/opt/lattice/bin/lattice-action-exec", "restart", "lattice-worker.service"]
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Could not start the restricted recovery helper: {exc}",
        )
    return {
        "status": "accepted",
        "action": "restart",
        "target": "lattice-worker.service",
        "message": "Restart requested; the master will verify recovery.",
    }
