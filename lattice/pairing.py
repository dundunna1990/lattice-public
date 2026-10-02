"""Master-side pairing client for a discovered Lattice worker."""
from __future__ import annotations

import ipaddress
import secrets
import socket
import subprocess
import time
import os
from pathlib import Path
import tempfile
import base64
import hashlib
import json
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from lattice.core.config import load_config
from lattice.core.crypto.ssh import ensure_lattice_ssh_key
from lattice.core.db import get_db_connection
from lattice.onboarding import PairingError, save_master_worker_token
from lattice.file_access.activation import (
    FleetActivationError,
    commit_worker_activation,
    discard_unacknowledged_worker_activation,
    stage_worker_activation,
)
from lattice.file_access.bootstrap import (
    FleetBootstrapError,
    ensure_master_fleet_bootstrap,
)
from lattice.file_access.membership import (
    FleetIdentityError,
    record_worker_file_identity,
    validate_worker_file_offer,
)
from lattice.file_access.transport_queue import (
    FileTransportQueueError,
    queue_transport_reconcile,
)
from lattice.file_access.mount_plan import (
    MountPlanError,
    build_mount_plan,
    write_mount_plan,
)
from lattice.ip_change.pool import (
    AddressPoolError,
    choose_available_address,
    read_address_pool,
)
from lattice.ip_change.assignment_auth import (
    NetworkAssignmentAuthError,
    sign_network_assignment,
)


def _refresh_master_peer_plan(manifest: dict) -> None:
    """Bind current active-node locators to one exact signed fleet generation."""
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """SELECT fn.node_id, COALESCE(w.ip, fn.last_known_ip) AS ip
               FROM fleet_nodes fn
               LEFT JOIN workers w ON w.id = fn.worker_id
               WHERE fn.membership_state='active'"""
        ).fetchall()
    finally:
        conn.close()
    locators = {str(row[0]): str(row[1]) for row in rows if row[1]}
    config = load_config()
    port = getattr(getattr(config, "file_access", None), "port", 22022)
    plan = build_mount_plan(manifest, locators, port=int(port))
    write_mount_plan(manifest, plan)


def reconcile_committed_worker_activation(
    hostname: str,
    *,
    worker_ip: str | None = None,
) -> dict:
    """Finish Master-local state for an already committed active worker."""
    conn = get_db_connection()
    try:
        worker = conn.execute(
            """SELECT id, ip FROM workers
               WHERE hostname=? AND removed_at IS NULL""",
            (hostname,),
        ).fetchone()
        if worker is None:
            raise PairingError("Committed worker record is unavailable")
        worker_id = int(worker["id"])
        active = conn.execute(
            """SELECT node_id FROM fleet_nodes
               WHERE worker_id=? AND membership_state='active' LIMIT 1""",
            (worker_id,),
        ).fetchone()
        if active is None:
            raise PairingError("Worker fleet membership is not committed")
        state = conn.execute(
            """SELECT generation, manifest, signature
               FROM fleet_state WHERE id=1"""
        ).fetchone()
        if state is None:
            raise PairingError("Committed fleet state is unavailable")
        try:
            manifest = json.loads(state["manifest"])
        except json.JSONDecodeError as exc:
            raise PairingError("Committed fleet manifest is invalid") from exc
        effective_ip = str(worker_ip or worker["ip"] or "")
        if not effective_ip:
            raise PairingError("Committed worker IP is unavailable")
    finally:
        conn.close()

    try:
        queue_transport_reconcile(manifest, str(state["signature"]))
        _refresh_master_peer_plan(manifest)
    except (FileTransportQueueError, MountPlanError, OSError, ValueError) as exc:
        raise PairingError(
            "Committed fleet membership could not reconcile local file/shell state: "
            f"{exc}"
        ) from exc

    conn = get_db_connection()
    try:
        conn.execute(
            """UPDATE workers
               SET status='healthy', ip=?, failure_count=0,
                   last_heartbeat_at=datetime('now')
               WHERE id=?""",
            (effective_ip, worker_id),
        )
        conn.execute(
            """UPDATE fleet_nodes SET last_known_ip=?
               WHERE worker_id=? AND membership_state='active'""",
            (effective_ip, worker_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "hostname": hostname,
        "node_id": str(active["node_id"]),
        "generation": int(state["generation"]),
        "ip": effective_ip,
        "status": "healthy",
    }


_SSH_USER_RE = __import__("re").compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def _pin_recovery_known_host(known_hosts: Path, host_alias: str, public_key: str) -> str:
    """Atomically pin one authenticated recovery-SSH host key by stable alias."""
    from lattice.file_access.keys import (
        FileKeyError,
        fingerprint_ed25519_public_key,
        validate_ed25519_public_key,
    )
    try:
        normalized = validate_ed25519_public_key(public_key)
        fingerprint = fingerprint_ed25519_public_key(normalized)
    except FileKeyError as exc:
        raise PairingError(f"Worker recovery SSH host key is invalid: {exc}") from exc
    if not host_alias or any(ch.isspace() for ch in host_alias) or "\x00" in host_alias:
        raise PairingError("Worker recovery SSH host alias is invalid")

    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if known_hosts.exists():
        existing = known_hosts.read_text(encoding="utf-8").splitlines()
    filtered = []
    for line in existing:
        fields = line.split()
        if fields and fields[0] == host_alias:
            continue
        filtered.append(line)
    fields = normalized.split()
    filtered.append(f"{host_alias} {fields[0]} {fields[1]}")

    fd, name = tempfile.mkstemp(dir=known_hosts.parent, prefix=f".{known_hosts.name}.")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o640)
            handle.write("\n".join(filtered) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if os.geteuid() == 0:
            try:
                import grp
                os.chown(temporary, 0, grp.getgrnam("lattice").gr_gid)
            except KeyError:
                pass
        os.replace(temporary, known_hosts)
        os.chmod(known_hosts, 0o640)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return fingerprint


def verify_worker_ssh(
    worker_ip, ssh_user, private_key_path, master_ip,
    expected_host_public_key, host_alias, runner=subprocess.run,
):
    """Prove restricted SSH access while requiring the authenticated host key."""
    known_hosts = private_key_path.parent / "known_hosts"
    ssh_fingerprint = _pin_recovery_known_host(
        known_hosts, host_alias, expected_host_public_key
    )
    command = [
        "ssh",
        "-i", str(private_key_path),
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"HostKeyAlias={host_alias}",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"BindAddress={master_ip}",
        f"{ssh_user}@{worker_ip}",
        "status lattice-worker.service",
    ]
    try:
        result = runner(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PairingError(f"Could not test SSH access to the worker: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "unknown SSH error").strip()
        raise PairingError(f"SSH access verification failed: {detail}")
    return ssh_fingerprint


def _assigned_worker_ips():
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT ip FROM workers WHERE removed_at IS NULL AND ip IS NOT NULL"
        ).fetchall()
        return {row[0] for row in rows}
    finally:
        conn.close()


def _address_is_in_use(interface, address):
    try:
        result = subprocess.run(
            ["arping", "-q", "-i", interface, "-c", "2", "-w", "3", address],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PairingError(f"Could not safely check address {address}: {exc}") from exc
    # This project targets Thomas Habets ARPing (the package installed by the
    # bootstrapper), not iputils arping.  For this implementation, a normal
    # probe exits 0 when at least one ARP reply is received and 1 when there
    # is no reply.  A reply means the candidate is already in use.
    if result.returncode == 0:
        return True
    if result.returncode == 1 and not (result.stderr or "").strip():
        return False
    detail = (result.stderr or result.stdout or "unknown arping failure").strip()[:300]
    raise PairingError(f"Could not safely check address {address}: {detail}")


def _active_pool_interface(pool, master_ip):
    """Resolve the interface that currently owns the Master's fleet address.

    The pool's saved interface is setup-time metadata and may become stale after
    Wi-Fi/Ethernet failover.  Address-conflict probes must follow the interface
    that actually owns the permanent Master address now.
    """
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PairingError(
            f"Could not determine the Master's active LAN interface: {exc}"
        ) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "ip addr failed").strip()[:300]
        raise PairingError(
            f"Could not determine the Master's active LAN interface: {detail}"
        )
    expected_network = ipaddress.IPv4Network(pool.network)
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != "inet":
            continue
        try:
            address = ipaddress.IPv4Interface(fields[3])
        except ValueError:
            continue
        if str(address.ip) == master_ip and address.ip in expected_network:
            return fields[1]
    raise PairingError(
        f"The Master address {master_ip} is not active on the configured LAN; "
        "refusing to probe worker addresses on a stale interface."
    )


def _automatic_network_assignment(master_ip, *, worker_hostname, worker_node_id):
    try:
        pool = read_address_pool()
    except AddressPoolError as exc:
        raise PairingError(f"The master address pool cannot be read safely: {exc}") from exc
    if pool is None:
        return None
    probe_interface = _active_pool_interface(pool, master_ip)
    reserved = _assigned_worker_ips() | {master_ip, pool.gateway}
    try:
        address = choose_available_address(
            pool,
            reserved,
            lambda candidate: _address_is_in_use(probe_interface, candidate),
        )
    except AddressPoolError as exc:
        raise PairingError(f"Could not choose a safe worker address: {exc}") from exc
    unsigned = {
        "assignment_id": str(uuid.uuid4()),
        "worker_hostname": worker_hostname,
        "worker_node_id": worker_node_id,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "address": address,
        "prefix": pool.prefix,
        "gateway": pool.gateway,
        "dns": list(pool.dns),
    }
    try:
        return sign_network_assignment(unsigned)
    except NetworkAssignmentAuthError as exc:
        raise PairingError(f"Could not authorize the worker network assignment: {exc}") from exc


def _wait_for_worker_at_address(address, hostname, port, token, attempts, retry_delay, sleeper, certificate):
    """Connect to the exact assigned IP while verifying the worker hostname."""
    server_name = __import__("lattice.core.pki", fromlist=["tls_hostname"]).tls_hostname(hostname)
    context = ssl.create_default_context(cafile=str(certificate))
    request = (
        f"GET /v1/network/assignment-status HTTP/1.1\r\nHost: {server_name}\r\n"
        f"Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    for attempt in range(attempts):
        try:
            with socket.create_connection((address, port), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=server_name) as secure:
                    secure.sendall(request)
                    response = b""
                    while len(response) <= 65536:
                        chunk = secure.recv(4096)
                        if not chunk:
                            break
                        response += chunk
            headers, _, body = response.partition(b"\r\n\r\n")
            if b" 200 " not in headers.split(b"\r\n", 1)[0]:
                raise PairingError("Worker assignment-status endpoint did not return success")
            result = json.loads(body.decode("utf-8"))
            if result.get("status") == "failed":
                raise PairingError(f"Worker could not apply {address}: {result.get('error', 'unknown error')}")
            if result.get("status") == "complete" and result.get("address") == address:
                return
        except (OSError, ssl.SSLError, ValueError):
            pass
        if attempt + 1 < attempts:
            sleeper(retry_delay)
    raise PairingError("Worker did not come back at its automatically assigned address.")


def _revoke_remote_pairing(base_url, token, certificate, sleeper=time.sleep) -> bool:
    """Request cleanup, then require public proof that the pairing is gone."""
    headers = {"Authorization": f"Bearer {token}"}
    verify_context = ssl.create_default_context(
        cafile=str(certificate)
    )
    try:
        response = httpx.post(
            f"{base_url}/v1/pairing/revoke",
            headers=headers,
            timeout=10,
            verify=verify_context,
        )
        if response.status_code != 202:
            return False
        for attempt in range(10):
            status = httpx.get(
                f"{base_url}/v1/pairing/status",
                timeout=5,
                verify=verify_context,
            )
            if status.status_code == 404:
                return True
            if attempt < 9:
                sleeper(1)
    except Exception:
        return False
    return False


def _verify_pairing_code_binds_certificate(*, code: str, certificate_pem: str, pairing_id: str, hostname: str) -> None:
    normalized = code.strip().upper()
    parts = normalized.split("-")
    if len(parts) != 2 or len(parts[0]) != 8 or len(parts[1]) != 6:
        raise PairingError("Pairing code has an invalid certificate-bound format")
    secret, supplied_tag = parts
    fingerprint = hashlib.sha256(certificate_pem.strip().encode("utf-8")).hexdigest()
    message = f"{fingerprint}|{pairing_id}|{hostname}".encode("utf-8")
    expected_tag = base64.b32encode(
        __import__("hmac").new(secret.encode("ascii"), message, hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")[:6]
    if not __import__("hmac").compare_digest(expected_tag, supplied_tag):
        raise PairingError("Worker TLS certificate was not authenticated by the pairing code")


def _pin_worker_certificate(hostname: str, certificate: str) -> Path:
    """Atomically store the worker certificate learned from its public offer."""
    if (
        not certificate.startswith("-----BEGIN CERTIFICATE-----")
        or not certificate.rstrip().endswith("-----END CERTIFICATE-----")
    ):
        raise PairingError("Worker pairing offer did not contain a valid encryption certificate")
    certificate_dir = Path(
        os.environ.get("LATTICE_WORKER_CERT_DIR", "/etc/lattice/worker-certs")
    )
    try:
        certificate_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=certificate_dir, prefix=f".{hostname}.", suffix=".tmp"
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o644)
                handle.write(certificate.rstrip() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            certificate_path = certificate_dir / f"{hostname}.crt"
            os.replace(temporary_path, certificate_path)
            certificate_path.chmod(0o644)
            return certificate_path
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise PairingError(f"Could not securely store the worker certificate: {exc}") from exc


def _activate_worker_after_network(
    *, hostname: str, assigned_ip: str, worker_identity, secure_base_url: str,
    worker_token: str, worker_tls_context,
) -> None:
    """Persist identity and complete one signed fleet activation transaction."""
    try:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE workers SET status='configuring', ip=?, "
                "last_heartbeat_at=datetime('now') "
                "WHERE hostname=? AND removed_at IS NULL",
                (assigned_ip, hostname),
            )
            worker_row = conn.execute(
                "SELECT id FROM workers WHERE hostname=? AND removed_at IS NULL",
                (hostname,),
            ).fetchone()
            if worker_row is None:
                raise PairingError(
                    "Verified worker disappeared before fleet identity persistence"
                )
            record_worker_file_identity(
                conn, worker_id=int(worker_row[0]), hostname=hostname,
                ip=assigned_ip, identity=worker_identity,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        conn = get_db_connection()
        try:
            candidate = stage_worker_activation(
                conn, target_node_id=worker_identity.node_id
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        activation_response = httpx.post(
            f"{secure_base_url}/v1/fleet/manifest",
            json={"manifest": candidate.manifest, "signature": candidate.signature},
            headers={"Authorization": f"Bearer {worker_token}"},
            timeout=15, verify=worker_tls_context,
        )
        if activation_response.status_code != 200:
            conn = get_db_connection()
            try:
                discard_unacknowledged_worker_activation(
                    conn,
                    target_node_id=worker_identity.node_id,
                    generation=candidate.generation,
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
            raise PairingError(
                "Worker rejected its signed fleet generation: "
                + activation_response.text[:200]
            )
        try:
            activation_ack = activation_response.json()
        except ValueError as exc:
            raise PairingError(
                "Worker fleet activation response was not valid JSON"
            ) from exc
        if (
            activation_ack.get("generation") != candidate.generation
            or activation_ack.get("node_id") != worker_identity.node_id
            or activation_ack.get("status") not in {"applied", "already_current"}
        ):
            # A 200 response with an unexpected body is ambiguous: the worker
            # may already have persisted the candidate. Preserve the durable
            # pending row so a later reconciliation can determine the truth.
            raise PairingError(
                "Worker did not acknowledge the expected fleet generation"
            )

        conn = get_db_connection()
        try:
            commit_worker_activation(
                conn, target_node_id=worker_identity.node_id,
                generation=candidate.generation,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

        reconcile_committed_worker_activation(
            hostname,
            worker_ip=assigned_ip,
        )
    except (httpx.HTTPError, FleetActivationError, PairingError, FleetIdentityError) as exc:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE workers SET status='needs_attention' "
                "WHERE hostname=? AND removed_at IS NULL",
                (hostname,),
            )
            conn.commit()
        finally:
            conn.close()
        if isinstance(exc, PairingError):
            raise
        raise PairingError(
            f"Worker paired but fleet activation is incomplete: {exc}"
        ) from exc


def refresh_worker_recovery_ssh_identity(hostname: str) -> str:
    """Upgrade one paired worker from TOFU to its TLS-authenticated SSH host key."""
    from lattice.core.worker_auth import read_worker_token, WorkerAuthError
    from lattice.core.pki import PKIError, tls_hostname
    from lattice.file_access.keys import (
        FileKeyError, fingerprint_ed25519_public_key, validate_ed25519_public_key,
    )

    try:
        worker_network_name = tls_hostname(hostname)
    except PKIError as exc:
        raise PairingError("Worker hostname is invalid") from exc

    config = load_config()
    port = config.wire_format.port
    certificate = Path(
        os.environ.get("LATTICE_WORKER_CERT_DIR", "/etc/lattice/worker-certs")
    ) / f"{hostname}.crt"
    if not certificate.is_file():
        raise PairingError("Pinned worker certificate is unavailable")
    try:
        token = read_worker_token(hostname)
    except WorkerAuthError as exc:
        raise PairingError(f"Saved worker credential is unavailable: {exc}") from exc

    context = ssl.create_default_context(cafile=str(certificate))
    try:
        response = httpx.get(
            f"https://{worker_network_name}:{port}/v1/fleet/identity",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
            verify=context,
        )
    except httpx.HTTPError as exc:
        raise PairingError(f"Could not read authenticated worker identity: {exc}") from exc
    if response.status_code != 200:
        raise PairingError(
            f"Worker identity endpoint returned HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise PairingError("Worker identity response was not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("hostname") != hostname:
        raise PairingError("Authenticated worker identity did not match the requested worker")

    public_key = payload.get("recovery_ssh_host_public_key")
    advertised = payload.get("recovery_ssh_host_key_fingerprint")
    try:
        public_key = validate_ed25519_public_key(public_key)
        expected = fingerprint_ed25519_public_key(public_key)
    except FileKeyError as exc:
        raise PairingError(f"Worker recovery SSH identity is invalid: {exc}") from exc
    if advertised != expected:
        raise PairingError("Worker recovery SSH host-key fingerprint does not match its key")

    private_key, _ = ensure_lattice_ssh_key()
    pinned = _pin_recovery_known_host(
        private_key.parent / "known_hosts", hostname, public_key
    )
    if pinned != expected:
        raise PairingError("Pinned recovery SSH fingerprint did not match authenticated identity")

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE workers SET ssh_host_key_fingerprint=? "
            "WHERE hostname=? AND removed_at IS NULL",
            (pinned, hostname),
        )
        if cursor.rowcount != 1:
            raise PairingError("Paired worker record was not found")
        conn.commit()
    finally:
        conn.close()
    return pinned


def repair_worker_network_assignment(hostname: str) -> dict:
    """Resume an interrupted post-approval pairing transaction safely.

    Reuses only already-established trust: the pinned Worker certificate and
    saved bearer token. It retrieves the Worker's canonical permanent public
    identity over that authenticated channel, finishes automatic IP assignment,
    and resumes signed fleet activation.
    """
    from lattice.core.worker_auth import read_worker_token, WorkerAuthError

    config = load_config()
    master_ip = config.master.ip
    port = config.wire_format.port

    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, ip, status FROM workers "
            "WHERE hostname=? AND removed_at IS NULL",
            (hostname,),
        ).fetchone()
        if row is None:
            raise PairingError(f"Worker {hostname} is not paired on this master")
        worker_id, current_ip, current_status = int(row[0]), str(row[1]), str(row[2])
        active = conn.execute(
            "SELECT node_id FROM fleet_nodes "
            "WHERE worker_id=? AND membership_state='active' LIMIT 1",
            (worker_id,),
        ).fetchone()
    finally:
        conn.close()

    certificate = Path(
        os.environ.get("LATTICE_WORKER_CERT_DIR", "/etc/lattice/worker-certs")
    ) / f"{hostname}.crt"
    if not certificate.is_file():
        raise PairingError("Pinned worker certificate is unavailable")
    try:
        token = read_worker_token(hostname)
    except WorkerAuthError as exc:
        raise PairingError(f"Saved worker credential is unavailable: {exc}") from exc

    worker_tls_context = ssl.create_default_context(cafile=str(certificate))
    secure_base_url = f"https://{hostname}.local:{port}"
    try:
        identity_response = httpx.get(
            f"{secure_base_url}/v1/fleet/identity",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10, verify=worker_tls_context,
        )
        if identity_response.status_code != 200:
            raise PairingError(
                "Worker could not provide its permanent fleet identity: "
                + identity_response.text[:200]
            )
        try:
            identity_payload = identity_response.json()
        except ValueError as exc:
            raise PairingError("Worker fleet identity response was not valid JSON") from exc
        try:
            worker_identity = validate_worker_file_offer(
                identity_payload, expected_hostname=hostname
            )
        except FleetIdentityError as exc:
            raise PairingError(f"Worker permanent fleet identity is invalid: {exc}") from exc

        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE workers SET status='configuring' WHERE id=?",
                (worker_id,),
            )
            conn.commit()
        finally:
            conn.close()

        assignment = _automatic_network_assignment(
            master_ip, worker_hostname=hostname, worker_node_id=worker_identity.node_id
        )
        if assignment is None:
            raise PairingError("No automatic address pool is configured on the master")
        response = httpx.post(
            f"{secure_base_url}/v1/network/assign",
            json=assignment,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10, verify=worker_tls_context,
        )
        if response.status_code != 202:
            raise PairingError(
                f"Worker rejected its automatic address: {response.text[:200]}"
            )
        assigned_ip = assignment["address"]
        _wait_for_worker_at_address(
            assigned_ip, hostname, port, token, 12, 2.0, time.sleep, certificate
        )

        if active is not None and str(active[0]) == worker_identity.node_id:
            reconcile_committed_worker_activation(
                hostname,
                worker_ip=assigned_ip,
            )
        else:
            _activate_worker_after_network(
                hostname=hostname, assigned_ip=assigned_ip,
                worker_identity=worker_identity, secure_base_url=secure_base_url,
                worker_token=token, worker_tls_context=worker_tls_context,
            )
    except (httpx.HTTPError, PairingError) as exc:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE workers SET status='needs_attention' WHERE id=?",
                (worker_id,),
            )
            conn.commit()
        finally:
            conn.close()
        if isinstance(exc, PairingError):
            raise
        raise PairingError(f"Could not resume worker pairing: {exc}") from exc

    return {
        "hostname": hostname, "old_ip": current_ip, "ip": assigned_ip,
        "previous_status": current_status, "status": "healthy",
    }


def _discard_unsigned_incomplete_enrollment(hostname: str) -> bool:
    """Discard only a failed pre-membership enrollment for a fresh retry.

    A real fleet identity is never touched here.  This exists so a Worker that
    was purged after pairing failed before fleet activation can be enrolled
    again without hand-editing the Master's database.
    """
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, status, removed_at FROM workers WHERE hostname=?",
            (hostname,),
        ).fetchone()
        if row is None or row[2] is not None:
            return False
        worker_id, status = int(row[0]), str(row[1])
        if status not in {"configuring", "needs_attention"}:
            return False
        if conn.execute(
            "SELECT 1 FROM fleet_nodes WHERE worker_id=? LIMIT 1",
            (worker_id,),
        ).fetchone() is not None:
            return False
        for table in (
            "services", "alerts", "events", "circuit_breaker_state",
            "healing_attempts",
        ):
            conn.execute(f"DELETE FROM {table} WHERE worker_id=?", (worker_id,))
        conn.execute(
            "DELETE FROM config WHERE key IN (?, ?)",
            (f"autoheal.enabled.{worker_id}", f"health.recheck.{worker_id}"),
        )
        conn.execute("DELETE FROM workers WHERE id=?", (worker_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    token_dir = Path(os.environ.get("LATTICE_TOKEN_DIR", "/etc/lattice/tokens"))
    certificate_dir = Path(
        os.environ.get("LATTICE_WORKER_CERT_DIR", "/etc/lattice/worker-certs")
    )
    (token_dir / f"{hostname}.token").unlink(missing_ok=True)
    (certificate_dir / f"{hostname}.crt").unlink(missing_ok=True)
    # The recovery known-host pin is replaced atomically later, but only after
    # the fresh pairing code has authenticated the new Worker certificate.
    return True


def pair_worker(
    *,
    hostname: str,
    worker_ip: str,
    pairing_id: str,
    code: str,
    ssh_user: str | None = None,
    master_hostname: str | None = None,
    master_ip: str | None = None,
    port: int = 9999,
    approval_wait_attempts: int = 150,
    approval_retry_delay: float = 2.0,
    sleeper=time.sleep,
    ssh_verifier=verify_worker_ssh,
    master_main_user: str | None = None,
) -> dict[str, Any]:
    """Pair an explicitly discovered worker after local approval.

    The worker is added to the master database only after it accepts the
    one-time code and the new bearer token successfully reads its service
    inventory. No worker is recorded as healthy before that verification.
    """
    try:
        from lattice.wizard.lifecycle import current_role
        role = current_role()
    except Exception:
        role = None
    if role != "master":
        raise PairingError(
            "Worker enrollment is available only on the Lattice Master."
        )
    try:
        worker_ip = str(ipaddress.ip_address(worker_ip))
    except ValueError as exc:
        raise PairingError("Worker IP address is invalid") from exc
    if not hostname or not pairing_id or not code:
        raise PairingError("Worker name, pairing ID, and code are all required")
    if ssh_user is not None and not _SSH_USER_RE.fullmatch(ssh_user):
        raise PairingError("SSH user has an invalid format")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise PairingError("Worker API port is invalid")

    from lattice.core.pki import PKIError, ensure_master_identity, tls_hostname
    try:
        worker_network_name = tls_hostname(hostname)
    except PKIError as exc:
        raise PairingError("Worker hostname is invalid") from exc

    # Never overwrite a real fleet identity.  One unsigned, incomplete row may
    # be replaced, but only after the fresh Worker's pairing code authenticates
    # its certificate below.
    conn = get_db_connection()
    try:
        existing_worker = conn.execute(
            "SELECT id, removed_at, status FROM workers WHERE hostname = ?",
            (hostname,),
        ).fetchone()
        stale_incomplete = False
        if existing_worker and existing_worker[1] is None:
            fleet_row = conn.execute(
                "SELECT 1 FROM fleet_nodes WHERE worker_id=? LIMIT 1",
                (existing_worker[0],),
            ).fetchone()
            stale_incomplete = (
                fleet_row is None
                and str(existing_worker[2]) in {"configuring", "needs_attention"}
            )
    finally:
        conn.close()
    if existing_worker and existing_worker[1] is None and not stale_incomplete:
        raise PairingError(f"A worker named '{hostname}' is already paired")

    config = load_config()
    master_hostname = master_hostname or socket.gethostname()
    master_ip = master_ip or config.master.ip
    try:
        master_ip = str(ipaddress.ip_address(master_ip))
    except ValueError as exc:
        raise PairingError("Master IP address is invalid") from exc

    conn = get_db_connection()
    try:
        master_fleet = ensure_master_fleet_bootstrap(
            conn,
            hostname=master_hostname,
            ip=master_ip,
            main_user=master_main_user,
        )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        if isinstance(exc, PairingError):
            raise
        if isinstance(exc, FleetBootstrapError):
            raise PairingError(
                f"Master fleet identity is unavailable: {exc}"
            ) from exc
        raise
    finally:
        conn.close()

    private_key_path, public_key_path = ensure_lattice_ssh_key()
    public_key = public_key_path.read_text(encoding="utf-8").strip()
    worker_token = secrets.token_urlsafe(48)
    master_identity = ensure_master_identity(master_hostname, master_ip)
    bootstrap_base_url = f"https://{worker_ip}:{port}"
    try:
        # This first request contains only the public offer. Verification is
        # disabled exactly once so the self-signed certificate can be learned;
        # no pairing code, token, or master credential is sent until it is pinned.
        offer_response = httpx.get(
            f"{bootstrap_base_url}/v1/pairing/status", timeout=10, verify=False
        )
    except httpx.HTTPError as exc:
        raise PairingError(f"Could not read the worker's secure pairing offer: {exc}") from exc
    if offer_response.status_code != 200:
        raise PairingError(
            f"Worker pairing offer returned HTTP {offer_response.status_code}"
        )
    try:
        offer_payload = offer_response.json()
    except ValueError as exc:
        raise PairingError("Worker pairing offer was not valid JSON") from exc
    if (
        offer_payload.get("state") != "waiting"
        or offer_payload.get("pairing_id") != pairing_id
        or offer_payload.get("hostname") != hostname
    ):
        raise PairingError("Worker pairing offer did not match the discovered worker")
    candidate_certificate = offer_payload.get("worker_certificate")
    if not isinstance(candidate_certificate, str):
        raise PairingError(
            "Worker pairing offer did not contain an encryption certificate"
        )

    try:
        worker_file_identity = validate_worker_file_offer(
            offer_payload,
            expected_hostname=hostname,
        )
    except FleetIdentityError as exc:
        raise PairingError(
            f"Worker pairing offer contained an invalid file identity: {exc}"
        ) from exc
    _verify_pairing_code_binds_certificate(
        code=code, certificate_pem=candidate_certificate,
        pairing_id=pairing_id, hostname=hostname,
    )
    if stale_incomplete:
        if not _discard_unsigned_incomplete_enrollment(hostname):
            raise PairingError(
                "The previous incomplete worker record changed during fresh enrollment; "
                "nothing was overwritten."
            )
        existing_worker = None
    recovery_ssh_host_public_key = offer_payload.get(
        "recovery_ssh_host_public_key"
    )
    recovery_ssh_host_key_fingerprint = offer_payload.get(
        "recovery_ssh_host_key_fingerprint"
    )
    from lattice.file_access.keys import (
        FileKeyError, fingerprint_ed25519_public_key, validate_ed25519_public_key,
    )
    try:
        recovery_ssh_host_public_key = validate_ed25519_public_key(
            recovery_ssh_host_public_key
        )
        expected_recovery_fingerprint = fingerprint_ed25519_public_key(
            recovery_ssh_host_public_key
        )
    except FileKeyError as exc:
        raise PairingError(f"Worker recovery SSH identity is invalid: {exc}") from exc
    if recovery_ssh_host_key_fingerprint != expected_recovery_fingerprint:
        raise PairingError("Worker recovery SSH host-key fingerprint does not match its key")
    worker_certificate = _pin_worker_certificate(hostname, candidate_certificate)
    worker_tls_context = ssl.create_default_context(
        cafile=str(worker_certificate)
    )
    secure_base_url = f"https://{worker_network_name}:{port}"

    payload = {
        "pairing_id": pairing_id,
        "code": code,
        "master_hostname": master_hostname,
        "master_ip": master_ip,
        "master_public_key": public_key,
        "fleet_id": master_fleet.fleet_id,
        "master_node_id": master_fleet.node_id,
        "master_file_public_key":
            master_fleet.file_public_key,
        "master_file_host_public_key":
            master_fleet.file_host_public_key,
        "master_file_host_key_fingerprint":
            master_fleet.file_host_key_fingerprint,
        "fleet_signing_public_key":
            master_fleet.fleet_signing_public_key,
        "worker_token": worker_token,
        "master_ca_certificate": master_identity["ca"].read_text(encoding="utf-8"),
        "master_api_port": getattr(config.master, "api_port", 8080),
    }
    if getattr(master_fleet, "shell_public_key", None):
        payload.update({
            "master_shell_public_key": master_fleet.shell_public_key,
            "master_shell_host_public_key": master_fleet.shell_host_public_key,
            "master_shell_host_key_fingerprint": master_fleet.shell_host_key_fingerprint,
        })
    try:
        response = httpx.post(
            f"{secure_base_url}/v1/pairing/confirm",
            json=payload,
            timeout=15,
            verify=worker_tls_context,
        )
    except httpx.HTTPError as exc:
        worker_certificate.unlink(missing_ok=True)
        raise PairingError(f"Could not reach the worker to pair it: {exc}") from exc
    if response.status_code != 202:
        detail = response.text[:200]
        try:
            detail = response.json().get("detail", detail)
        except ValueError:
            pass
        worker_certificate.unlink(missing_ok=True)
        raise PairingError(f"Worker rejected pairing request: {detail}")

    try:
        raw_confirm_payload = response.json()
    except (ValueError, TypeError):
        raw_confirm_payload = {}
    confirm_payload = raw_confirm_payload if isinstance(raw_confirm_payload, dict) else {}
    confirmed_ssh_user = confirm_payload.get("ssh_user")
    if confirmed_ssh_user is not None:
        if not isinstance(confirmed_ssh_user, str) or not _SSH_USER_RE.fullmatch(confirmed_ssh_user):
            worker_certificate.unlink(missing_ok=True)
            raise PairingError("Worker returned an invalid SSH user after code verification")
        if ssh_user is not None and not hmac.compare_digest(confirmed_ssh_user, ssh_user):
            worker_certificate.unlink(missing_ok=True)
            raise PairingError("Worker SSH user did not match the requested account")
        ssh_user = confirmed_ssh_user
    if ssh_user is None:
        worker_certificate.unlink(missing_ok=True)
        raise PairingError(
            "Worker did not provide its SSH user after code verification"
        )

    if worker_file_identity.main_user != ssh_user:
        worker_certificate.unlink(missing_ok=True)
        raise PairingError(
            "Worker file identity belongs to a different main user"
        )

    # The worker owner must approve this exact request locally.  Poll only the
    # non-secret public status; no credentials are usable until it is paired.
    for attempt in range(approval_wait_attempts):
        try:
            status = httpx.get(
                f"{secure_base_url}/v1/pairing/status",
                timeout=10,
                verify=worker_tls_context,
            )
        except httpx.HTTPError:
            status = None
        if status is not None and status.status_code == 200:
            try:
                status_payload = status.json()
            except ValueError:
                status_payload = {}
            if (
                status_payload.get("state") == "paired"
                and status_payload.get("pairing_id") == pairing_id
                and status_payload.get("hostname") == hostname
            ):
                break
        if attempt + 1 < approval_wait_attempts:
            sleeper(approval_retry_delay)
    else:
        worker_certificate.unlink(missing_ok=True)
        raise PairingError(
            "The worker was not approved in time. On that worker, approve the "
            "pending request locally, then try again."
        )

    # The new token must work before we persist this worker as paired.
    try:
        verification = httpx.get(
            f"{secure_base_url}/v1/services",
            headers={"Authorization": f"Bearer {worker_token}"},
            timeout=10,
            verify=worker_tls_context,
        )
    except httpx.HTTPError as exc:
        cleaned = _revoke_remote_pairing(
            secure_base_url, worker_token, worker_certificate, sleeper
        )
        if cleaned:
            worker_certificate.unlink(missing_ok=True)
        suffix = "" if cleaned else " Local revocation is still required on the worker."
        raise PairingError(f"Worker accepted pairing but verification failed: {exc}.{suffix}") from exc
    if verification.status_code != 200:
        cleaned = _revoke_remote_pairing(
            secure_base_url, worker_token, worker_certificate, sleeper
        )
        if cleaned:
            worker_certificate.unlink(missing_ok=True)
        suffix = "" if cleaned else " Local revocation is still required on the worker."
        raise PairingError(
            f"Worker accepted pairing but token verification returned HTTP {verification.status_code}."
            f"{suffix}"
        )

    try:
        ssh_fingerprint = ssh_verifier(
            worker_ip, ssh_user, private_key_path, master_ip,
            recovery_ssh_host_public_key, hostname,
        )
        if not isinstance(ssh_fingerprint, str) or not ssh_fingerprint.startswith("SHA256:"):
            raise PairingError("SSH verification did not return a trusted worker host-key fingerprint")
    except PairingError as exc:
        cleaned = _revoke_remote_pairing(
            secure_base_url, worker_token, worker_certificate, sleeper
        )
        if cleaned:
            worker_certificate.unlink(missing_ok=True)
        suffix = "" if cleaned else " Local revocation is still required on the worker."
        raise PairingError(f"{exc}.{suffix}") from exc

    # Record the currently reachable discovery address while the worker is
    # being configured; this is replaced only after it returns at the new one.
    assigned_ip = worker_ip
    try:
        token_path = save_master_worker_token(hostname, worker_token)
        conn = get_db_connection()
        try:
            if existing_worker:
                conn.execute(
                    """
                    UPDATE workers
                    SET status = 'configuring', ssh_user = ?, ip = ?, ssh_host_key_fingerprint = ?,
                        last_heartbeat_at = datetime('now'), failure_count = 0,
                        removed_at = NULL
                    WHERE id = ? AND removed_at IS NOT NULL
                    """,
                    (ssh_user, assigned_ip, ssh_fingerprint, existing_worker[0]),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO workers (hostname, status, ssh_user, ip, ssh_host_key_fingerprint, last_heartbeat_at)
                    VALUES (?, 'configuring', ?, ?, ?, datetime('now'))
                    """,
                    (hostname, ssh_user, assigned_ip, ssh_fingerprint),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:
        cleaned = _revoke_remote_pairing(
            secure_base_url, worker_token, worker_certificate, sleeper
        )
        if cleaned:
            token_path = locals().get("token_path")
            if token_path is not None:
                token_path.unlink(missing_ok=True)
            worker_certificate.unlink(missing_ok=True)
        if isinstance(exc, PairingError):
            raise
        raise PairingError(
            "Could not persist the verified worker; "
            + ("remote credentials were cleaned up." if cleaned else "local revocation is required on the worker.")
        ) from exc

    # The master reserves the next address from its own pool.  It checks the
    # live LAN before sending it, then the worker checks again immediately
    # before applying it.  This two-sided check prevents duplicate addresses.
    try:
        assignment = _automatic_network_assignment(
            master_ip, worker_hostname=hostname, worker_node_id=worker_file_identity.node_id
        )
        if assignment is None:
            raise PairingError(
                "No automatic address pool is configured on the master. "
                "Finish master network setup before pairing workers."
            )
        assignment_response = httpx.post(
            f"{secure_base_url}/v1/network/assign",
            json=assignment,
            headers={"Authorization": f"Bearer {worker_token}"},
            timeout=10,
            verify=worker_tls_context,
        )
        if assignment_response.status_code != 202:
            raise PairingError(
                f"Worker rejected its automatic address: {assignment_response.text[:200]}"
            )
        assigned_ip = assignment["address"]
        _wait_for_worker_at_address(
            assigned_ip,
            hostname,
            port,
            worker_token,
            12,
            2.0,
            sleeper,
            worker_certificate,
        )
    except (httpx.HTTPError, PairingError) as exc:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE workers SET status = 'needs_attention' WHERE hostname = ? AND removed_at IS NULL",
                (hostname,),
            )
            conn.commit()
        finally:
            conn.close()
        if isinstance(exc, PairingError):
            raise
        raise PairingError(f"Could not send the worker its automatic address: {exc}") from exc

    _activate_worker_after_network(
        hostname=hostname,
        assigned_ip=assigned_ip,
        worker_identity=worker_file_identity,
        secure_base_url=secure_base_url,
        worker_token=worker_token,
        worker_tls_context=worker_tls_context,
    )

    return {
        "hostname": hostname,
        "ip": assigned_ip,
        "ssh_user": ssh_user,
        "status": "paired",
    }
