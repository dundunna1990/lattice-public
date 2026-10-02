"""Worker-first onboarding and one-time-code pairing for Lattice.

The code in this module is deliberately independent from the terminal UI.
The UI asks the questions; these functions enforce the pairing rules and keep
the sensitive state on disk with private permissions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
import pwd
import grp
import subprocess
import stat
from typing import Any


DEFAULT_PAIRING_STATE_PATH = Path("/var/lib/lattice/pairing.json")
DEFAULT_TOKEN_DIR = Path("/etc/lattice/tokens")
DEFAULT_AUTHORIZED_KEYS_PATH = Path("/etc/lattice/keys/authorized_keys")
DEFAULT_PAIRING_HELPER = Path("/opt/lattice/bin/lattice-pairing-exec")
DEFAULT_MASTER_ENDPOINT_PATH = Path("/var/lib/lattice/master-endpoint.json")
DEFAULT_FLEET_BOOTSTRAP_PATH = Path("/etc/lattice/fleet/bootstrap.json")
DEFAULT_RECOVERY_SSH_HOST_KEY_PATH = Path("/etc/ssh/ssh_host_ed25519_key.pub")

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
_SSH_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class PairingError(ValueError):
    """Raised when a worker pairing request is invalid or cannot proceed."""


def _recovery_ssh_host_identity() -> tuple[str, str]:
    """Return the local system SSH Ed25519 host key and its fingerprint safely."""
    path = Path(os.environ.get(
        "LATTICE_RECOVERY_SSH_HOST_KEY_PATH",
        str(DEFAULT_RECOVERY_SSH_HOST_KEY_PATH),
    ))
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PairingError(f"Recovery SSH host key is unavailable: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PairingError("Recovery SSH host key path is unsafe")
    if metadata.st_mode & 0o022:
        raise PairingError("Recovery SSH host key permissions are unsafe")
    try:
        value = path.read_text(encoding="utf-8").strip()
        from lattice.file_access.keys import (
            FileKeyError, fingerprint_ed25519_public_key, validate_ed25519_public_key,
        )
        value = validate_ed25519_public_key(value)
        fingerprint = fingerprint_ed25519_public_key(value)
    except (OSError, FileKeyError) as exc:
        raise PairingError(f"Recovery SSH host key is invalid: {exc}") from exc
    return value, fingerprint


@dataclass(frozen=True)
class PairingOffer:
    pairing_id: str
    code: str
    hostname: str
    ssh_user: str
    expires_at: str
    node_id: str
    main_user: str
    main_uid: int
    main_gid: int
    file_public_key: str
    file_host_public_key: str
    file_host_key_fingerprint: str
    file_key_generation: int
    shell_public_key: str
    shell_host_public_key: str
    shell_host_key_fingerprint: str
    shell_key_generation: int
    backup_public_key: str
    backup_host_public_key: str
    backup_host_key_fingerprint: str
    backup_key_generation: int
    recovery_ssh_host_public_key: str
    recovery_ssh_host_key_fingerprint: str


def _state_path() -> Path:
    return Path(os.environ.get("LATTICE_PAIRING_STATE_PATH", DEFAULT_PAIRING_STATE_PATH))


def _token_dir() -> Path:
    return Path(os.environ.get("LATTICE_TOKEN_DIR", DEFAULT_TOKEN_DIR))


def _authorized_keys_path() -> Path:
    return Path(os.environ.get("LATTICE_AUTHORIZED_KEYS_PATH", DEFAULT_AUTHORIZED_KEYS_PATH))


def _fleet_bootstrap_path() -> Path:
    override = os.environ.get("LATTICE_FLEET_BOOTSTRAP_PATH")
    if override:
        return Path(override)

    if os.environ.get("LATTICE_PAIRING_STATE_PATH"):
        return _state_path().parent / "fleet-bootstrap.json"

    return DEFAULT_FLEET_BOOTSTRAP_PATH


def _master_endpoint_path() -> Path:
    override = os.environ.get("LATTICE_MASTER_ENDPOINT_PATH")
    if override:
        return Path(override)
    # Isolated tests redirect pairing state to a temporary directory.
    if os.environ.get("LATTICE_PAIRING_STATE_PATH"):
        return _state_path().parent / "master-endpoint.json"
    return DEFAULT_MASTER_ENDPOINT_PATH


def get_worker_master_endpoint() -> dict[str, Any] | None:
    path = _master_endpoint_path()
    if not path.exists():
        return None
    try:
        payload = _read_private_json(path)
        ipaddress.ip_address(payload["ip"])
        port = int(payload.get("port", 8080))
        if not 1 <= port <= 65535:
            raise ValueError("port outside range")
        result = {"ip": str(payload["ip"]), "port": port}
        if payload.get("hostname"):
            result["hostname"] = _validate_hostname(str(payload["hostname"]))
        return result
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PairingError(f"Saved master endpoint is invalid: {exc}") from exc


def _write_worker_master_endpoint(
    master_ip: str, port: int = 8080, hostname: str | None = None
) -> None:
    payload: dict[str, Any] = {"ip": master_ip, "port": port}
    if hostname:
        payload["hostname"] = _validate_hostname(hostname)
    _write_private_json(_master_endpoint_path(), payload)


def _install_pairing_credentials(request: dict[str, Any]) -> None:
    """Test-only direct installer for isolated temporary-path tests.

    Production pairing never calls this function; it uses the locally
    approved root-owned ``lattice-pairing-exec`` helper.
    """
    if os.environ.get("LATTICE_PAIRING_TEST_DIRECT") != "1":
        raise PairingError("Direct pairing credential installation is test-only; production requires the root-approved local pairing helper")
    from lattice.core.crypto.ssh import install_restricted_authorized_key_text

    install_restricted_authorized_key_text(
        request["master_public_key"],
        allowed_cidr=f"{request['master_ip']}/32",
        authorized_keys_path=_authorized_keys_path(),
    )
    _write_worker_token(request["hostname"], request["worker_token"])

    _write_private_json(
        _fleet_bootstrap_path(),
        {
            "fleet_id": request["fleet_id"],
            "master_node_id": request["master_node_id"],
            "master_file_public_key":
                request["master_file_public_key"],
            "master_file_host_public_key":
                request["master_file_host_public_key"],
            "master_file_host_key_fingerprint":
                request["master_file_host_key_fingerprint"],
            "master_shell_public_key": request.get("master_shell_public_key"),
            "master_shell_host_public_key": request.get("master_shell_host_public_key"),
            "master_shell_host_key_fingerprint": request.get("master_shell_host_key_fingerprint"),
            "fleet_signing_public_key":
                request["fleet_signing_public_key"],
            "approved_at": _utc_now().isoformat(),
        },
    )
    return


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_private_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(data, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_private_json(path: Path, maximum: int = 32768) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PairingError(f"{path} is not a single regular file")
        allowed_uids = {0, os.geteuid()}
        try:
            allowed_uids.add(pwd.getpwnam("lattice").pw_uid)
        except KeyError:
            pass
        if metadata.st_uid not in allowed_uids or metadata.st_mode & 0o022:
            raise PairingError(f"{path} has unsafe ownership or permissions")
        if metadata.st_size > maximum:
            raise PairingError(f"{path} is too large")
        raw = os.read(descriptor, maximum + 1)
    finally:
        os.close(descriptor)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PairingError(f"{path} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise PairingError(f"{path} has an invalid format")
    return data


def _make_lattice_owned_if_available(path: Path) -> None:
    """Let the unprivileged worker service read its own pairing state."""
    if os.environ.get("LATTICE_PAIRING_STATE_PATH"):
        return
    try:
        account = pwd.getpwnam("lattice")
        group = grp.getgrnam("lattice")
    except KeyError:
        return
    os.chown(path, account.pw_uid, group.gr_gid)
    os.chmod(path, 0o600)


def _load_state() -> dict[str, Any] | None:
    path = _state_path()
    if not path.exists():
        return None
    try:
        data = _read_private_json(path)
    except (OSError, PairingError) as exc:
        raise PairingError(f"Pairing state cannot be read safely: {exc}") from exc
    return data


def _generate_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(alphabet) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def _hash_code(code: str, salt: bytes) -> str:
    digest = hashlib.scrypt(code.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(digest).decode("ascii")


def _certificate_fingerprint(certificate_pem: str) -> str:
    return hashlib.sha256(certificate_pem.strip().encode("utf-8")).hexdigest()


def _generate_certificate_bound_code(certificate_pem: str, pairing_id: str, hostname: str) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    secret = "".join(secrets.choice(alphabet) for _ in range(8))
    message = f"{_certificate_fingerprint(certificate_pem)}|{pairing_id}|{hostname}".encode("utf-8")
    tag = base64.b32encode(hmac.new(secret.encode("ascii"), message, hashlib.sha256).digest()).decode("ascii").rstrip("=")[:6]
    return f"{secret}-{tag}"


def _validate_hostname(hostname: str) -> str:
    value = hostname.strip()
    if not _HOSTNAME_RE.fullmatch(value):
        raise PairingError("Worker hostname has an invalid format")
    return value


def _validate_ssh_user(ssh_user: str) -> str:
    value = ssh_user.strip()
    if not _SSH_USER_RE.fullmatch(value):
        raise PairingError("SSH user has an invalid format")
    return value


def prepare_worker_pairing(hostname: str, ssh_user: str, expires_in_seconds: int = 600) -> PairingOffer:
    """Put a worker into short-lived, unpaired discovery mode.

    Only a salted hash of the displayed code is written to disk. Discovery
    records publish the pairing ID and state, never the code itself.
    """
    if expires_in_seconds < 60 or expires_in_seconds > 3600:
        raise PairingError("Pairing code lifetime must be between 60 seconds and one hour")
    hostname = _validate_hostname(hostname)
    ssh_user = _validate_ssh_user(ssh_user)

    from lattice.file_access.profile import ensure_local_file_profile

    try:
        file_profile = ensure_local_file_profile(ssh_user)
    except Exception as exc:
        raise PairingError(
            f"Could not prepare this worker's permanent file identity: {exc}"
        ) from exc

    from lattice.core.pki import ensure_worker_identity
    worker_certificate = ensure_worker_identity(hostname)["cert"].read_text(encoding="utf-8")
    recovery_ssh_host_public_key, recovery_ssh_host_key_fingerprint = (
        _recovery_ssh_host_identity()
    )
    pairing_id = secrets.token_urlsafe(24)
    code = _generate_certificate_bound_code(worker_certificate, pairing_id, hostname)
    salt = secrets.token_bytes(16)
    expires_at = _utc_now() + timedelta(seconds=expires_in_seconds)
    offer = PairingOffer(
        pairing_id=pairing_id,
        code=code,
        hostname=hostname,
        ssh_user=ssh_user,
        expires_at=expires_at.isoformat(),
        node_id=file_profile.node_id,
        main_user=file_profile.main_user,
        main_uid=file_profile.main_uid,
        main_gid=file_profile.main_gid,
        file_public_key=file_profile.client.public_key_text,
        file_host_public_key=file_profile.host.public_key_text,
        file_host_key_fingerprint=file_profile.host.fingerprint,
        file_key_generation=1,
        shell_public_key=file_profile.shell_client.public_key_text,
        shell_host_public_key=file_profile.shell_host.public_key_text,
        shell_host_key_fingerprint=file_profile.shell_host.fingerprint,
        shell_key_generation=1,
        backup_public_key=file_profile.backup_client.public_key_text,
        backup_host_public_key=file_profile.backup_host.public_key_text,
        backup_host_key_fingerprint=file_profile.backup_host.fingerprint,
        backup_key_generation=1,
        recovery_ssh_host_public_key=recovery_ssh_host_public_key,
        recovery_ssh_host_key_fingerprint=recovery_ssh_host_key_fingerprint,
    )
    _write_private_json(
        _state_path(),
        {
            "state": "waiting",
            "pairing_id": offer.pairing_id,
            "hostname": hostname,
            "ssh_user": ssh_user,
            "expires_at": offer.expires_at,
            "code_salt": base64.b64encode(salt).decode("ascii"),
            "code_hash": _hash_code(code, salt),
            "attempts": 0,
            "attempts_by_ip": {},
            "worker_certificate": worker_certificate,
            "node_id": offer.node_id,
            "main_user": offer.main_user,
            "main_uid": offer.main_uid,
            "main_gid": offer.main_gid,
            "file_public_key": offer.file_public_key,
            "file_host_public_key": offer.file_host_public_key,
            "file_host_key_fingerprint":
                offer.file_host_key_fingerprint,
            "file_key_generation": offer.file_key_generation,
            "shell_public_key": offer.shell_public_key,
            "shell_host_public_key": offer.shell_host_public_key,
            "shell_host_key_fingerprint": offer.shell_host_key_fingerprint,
            "shell_key_generation": offer.shell_key_generation,
            "backup_public_key": offer.backup_public_key,
            "backup_host_public_key": offer.backup_host_public_key,
            "backup_host_key_fingerprint": offer.backup_host_key_fingerprint,
            "backup_key_generation": offer.backup_key_generation,
            "recovery_ssh_host_public_key": offer.recovery_ssh_host_public_key,
            "recovery_ssh_host_key_fingerprint": offer.recovery_ssh_host_key_fingerprint,
        },
    )
    _make_lattice_owned_if_available(_state_path())
    return offer


def get_public_pairing_status() -> dict[str, Any] | None:
    """Return the non-secret information a master may learn during discovery."""
    state = _load_state()
    if not state or state.get("state") not in {"waiting", "awaiting_approval", "paired"}:
        return None
    if state.get("state") == "paired":
        return {
            "state": "paired",
            "pairing_id": state["pairing_id"],
            "hostname": state["hostname"],
        }
    if state.get("state") == "awaiting_approval":
        try:
            approval_expires_at = datetime.fromisoformat(state["approval_expires_at"])
            if approval_expires_at.tzinfo is None:
                raise ValueError("timezone is missing")
        except (KeyError, TypeError, ValueError) as exc:
            raise PairingError("Pending pairing state has an invalid expiration") from exc
        if approval_expires_at <= _utc_now():
            state = {
                "state": "expired",
                "pairing_id": state.get("pairing_id", ""),
                "hostname": state.get("hostname", ""),
                "expired_at": _utc_now().isoformat(),
            }
            _write_private_json(_state_path(), state)
            _make_lattice_owned_if_available(_state_path())
            return None
        return {
            "state": "awaiting_approval",
            "pairing_id": state["pairing_id"],
            "hostname": state["hostname"],
            "master_hostname": state["master_hostname"],
        }
    try:
        expires_at = datetime.fromisoformat(state["expires_at"])
        if expires_at.tzinfo is None:
            raise ValueError("timezone is missing")
    except (KeyError, ValueError) as exc:
        raise PairingError("Pairing state has an invalid expiration") from exc
    if expires_at <= _utc_now():
        state["state"] = "expired"
        _write_private_json(_state_path(), state)
        return None
    return {
        "state": "waiting",
        "pairing_id": state["pairing_id"],
        "hostname": state["hostname"],
        "expires_at": state["expires_at"],
        "worker_certificate": state["worker_certificate"],
        "node_id": state["node_id"],
        "main_user": state["main_user"],
        "main_uid": state["main_uid"],
        "main_gid": state["main_gid"],
        "file_public_key": state["file_public_key"],
        "file_host_public_key": state["file_host_public_key"],
        "file_host_key_fingerprint":
            state["file_host_key_fingerprint"],
        "file_key_generation": state["file_key_generation"],
        "shell_public_key": state["shell_public_key"],
        "shell_host_public_key": state["shell_host_public_key"],
        "shell_host_key_fingerprint": state["shell_host_key_fingerprint"],
        "shell_key_generation": state["shell_key_generation"],
        "backup_public_key": state["backup_public_key"],
        "backup_host_public_key": state["backup_host_public_key"],
        "backup_host_key_fingerprint": state["backup_host_key_fingerprint"],
        "backup_key_generation": state["backup_key_generation"],
        "recovery_ssh_host_public_key": state["recovery_ssh_host_public_key"],
        "recovery_ssh_host_key_fingerprint": state["recovery_ssh_host_key_fingerprint"],
    }


def _validate_master_public_key(public_key: str) -> str:
    if not isinstance(public_key, str) or "\n" in public_key or "\r" in public_key:
        raise PairingError("Master public key must be a single line")
    value = public_key.strip()
    fields = value.split()
    if len(fields) not in (2, 3) or fields[0] != "ssh-ed25519":
        raise PairingError("Only an SSH Ed25519 public key may be paired")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except Exception as exc:
        raise PairingError("Master public key is not valid base64") from exc
    try:
        algorithm_length = int.from_bytes(decoded[0:4], "big")
        algorithm_end = 4 + algorithm_length
        algorithm = decoded[4:algorithm_end]
        key_length = int.from_bytes(decoded[algorithm_end:algorithm_end + 4], "big")
        key_start = algorithm_end + 4
        key_end = key_start + key_length
    except Exception as exc:
        raise PairingError("Master public key is not a valid Ed25519 key") from exc
    if (
        algorithm != b"ssh-ed25519"
        or key_length != 32
        or key_end != len(decoded)
    ):
        raise PairingError("Master public key is not a valid Ed25519 key")
    return value


def _write_worker_token(hostname: str, token: str) -> Path:
    if (
        not isinstance(token, str)
        or not 32 <= len(token) <= 512
        or "\n" in token
        or "\r" in token
    ):
        raise PairingError("Pairing token must be a single line between 32 and 512 characters")
    token_path = _token_dir() / f"{hostname}.token"
    token_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=token_path.parent, prefix=f".{token_path.name}.", suffix=".tmp"
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(token + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if not os.environ.get("LATTICE_TOKEN_DIR") and os.geteuid() == 0:
            try:
                lattice_group = grp.getgrnam("lattice")
            except KeyError as exc:
                raise PairingError("The lattice service group is unavailable") from exc
            os.chown(temporary_path, 0, lattice_group.gr_gid)
            os.chmod(temporary_path, 0o640)
        os.replace(temporary_path, token_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise
    return token_path


def confirm_worker_pairing(
    *,
    pairing_id: str,
    code: str,
    master_hostname: str,
    master_ip: str,
    master_public_key: str,
    fleet_id: str,
    master_node_id: str,
    master_file_public_key: str,
    master_file_host_public_key: str,
    master_file_host_key_fingerprint: str,
    master_shell_public_key: str | None = None,
    master_shell_host_public_key: str | None = None,
    master_shell_host_key_fingerprint: str | None = None,
    fleet_signing_public_key: str,
    worker_token: str,
    master_ca_certificate: str = "",
    master_api_port: int = 8080,
    source_ip: str = "unknown",
) -> dict[str, str]:
    """Validate a master request, then wait for approval on the worker itself.

    The network-facing worker service is never allowed to install SSH access.
    It can only record a short-lived request after the worker's displayed code
    is proven.  A person at the worker must separately approve that exact
    pairing ID through the root-owned helper.
    """
    state = get_public_pairing_status()
    if state is None:
        raise PairingError("Worker is not currently waiting to be paired")
    stored = _load_state()
    assert stored is not None
    if stored.get("state") != "waiting":
        raise PairingError("Worker already has a pairing request in progress")
    if not hmac.compare_digest(pairing_id, stored["pairing_id"]):
        raise PairingError("Pairing ID does not match this worker")
    now = _utc_now()
    attempts_by_ip = stored.get("attempts_by_ip", {})
    if not isinstance(attempts_by_ip, dict):
        attempts_by_ip = {}
    source_key = str(source_ip or "unknown")[:64]
    source_state = attempts_by_ip.get(source_key, {})
    if not isinstance(source_state, dict):
        source_state = {}
    retry_at_text = source_state.get("retry_at")
    if retry_at_text:
        try:
            retry_at = datetime.fromisoformat(str(retry_at_text))
            if retry_at.tzinfo is None:
                raise ValueError("timezone is missing")
        except ValueError:
            retry_at = now
        if retry_at > now:
            wait = max(1, int((retry_at - now).total_seconds() + 0.999))
            raise PairingError(f"Too many pairing attempts from this address; retry in {wait}s")

    supplied_code = code.strip().upper()
    salt = base64.b64decode(stored["code_salt"])
    expected_hash = stored["code_hash"]
    if not hmac.compare_digest(_hash_code(supplied_code, salt), expected_hash):
        total_attempts = int(stored.get("attempts", 0)) + 1
        per_ip_attempts = int(source_state.get("attempts", 0)) + 1
        stored["attempts"] = total_attempts
        delay_seconds = min(4, 2 ** (per_ip_attempts - 1))
        attempts_by_ip[source_key] = {
            "attempts": per_ip_attempts,
            "retry_at": (now + timedelta(seconds=delay_seconds)).isoformat(),
        }
        stored["attempts_by_ip"] = attempts_by_ip
        if total_attempts >= 5:
            expired = {
                "state": "expired",
                "pairing_id": stored.get("pairing_id", ""),
                "hostname": stored.get("hostname", ""),
                "expired_at": now.isoformat(),
                "reason": "too_many_incorrect_codes",
            }
            _write_private_json(_state_path(), expired)
            _make_lattice_owned_if_available(_state_path())
            raise PairingError(
                "Pairing code expired after too many incorrect attempts; start pairing again locally to issue a new code"
            )
        _write_private_json(_state_path(), stored)
        _make_lattice_owned_if_available(_state_path())
        raise PairingError("Pairing code is incorrect")

    master_hostname = _validate_hostname(master_hostname)
    try:
        normalized_master_ip = str(ipaddress.ip_address(master_ip.strip()))
    except ValueError as exc:
        raise PairingError("Master IP address is invalid") from exc
    public_key = _validate_master_public_key(master_public_key)

    from lattice.file_access.bootstrap import (
        FleetBootstrapError,
        validate_master_bootstrap,
    )

    try:
        master_file_bootstrap = validate_master_bootstrap(
            fleet_id=fleet_id,
            master_node_id=master_node_id,
            master_file_public_key=master_file_public_key,
            master_file_host_public_key=
                master_file_host_public_key,
            master_file_host_key_fingerprint=
                master_file_host_key_fingerprint,
            master_shell_public_key=master_shell_public_key,
            master_shell_host_public_key=master_shell_host_public_key,
            master_shell_host_key_fingerprint=master_shell_host_key_fingerprint,
            fleet_signing_public_key=
                fleet_signing_public_key,
        )
    except FleetBootstrapError as exc:
        raise PairingError(
            f"Master file/fleet identity is invalid: {exc}"
        ) from exc

    if isinstance(master_api_port, bool) or not isinstance(master_api_port, int) or not 1 <= master_api_port <= 65535:
        raise PairingError("Master API port is invalid")
    if (
        not isinstance(worker_token, str)
        or not 32 <= len(worker_token) <= 512
        or "\n" in worker_token
        or "\r" in worker_token
    ):
        raise PairingError("Worker token must be a single line between 32 and 512 characters")
    if os.environ.get("LATTICE_PAIRING_TEST_DIRECT") != "1":
        if (
            not isinstance(master_ca_certificate, str)
            or not master_ca_certificate.startswith("-----BEGIN CERTIFICATE-----")
            or not master_ca_certificate.rstrip().endswith("-----END CERTIFICATE-----")
        ):
            raise PairingError("Master encryption certificate is missing or invalid")

    request = {
        "state": "awaiting_approval",
        "pairing_id": stored["pairing_id"],
        "hostname": stored["hostname"],
        "ssh_user": stored["ssh_user"],
        "master_hostname": master_hostname,
        "master_ip": normalized_master_ip,
        "master_public_key": public_key,
        "fleet_id": master_file_bootstrap["fleet_id"],
        "master_node_id":
            master_file_bootstrap["master_node_id"],
        "master_file_public_key":
            master_file_bootstrap["master_file_public_key"],
        "master_file_host_public_key":
            master_file_bootstrap["master_file_host_public_key"],
        "master_file_host_key_fingerprint":
            master_file_bootstrap[
                "master_file_host_key_fingerprint"
            ],
        "fleet_signing_public_key":
            master_file_bootstrap["fleet_signing_public_key"],
        "worker_token": worker_token,
        "master_ca_certificate": master_ca_certificate,
        "master_api_port": master_api_port,
        "worker_certificate": stored.get("worker_certificate", ""),
        "requested_at": _utc_now().isoformat(),
        "approval_expires_at": stored["expires_at"],
    }
    if "master_shell_public_key" in master_file_bootstrap:
        request.update({
            "master_shell_public_key": master_file_bootstrap["master_shell_public_key"],
            "master_shell_host_public_key": master_file_bootstrap["master_shell_host_public_key"],
            "master_shell_host_key_fingerprint": master_file_bootstrap["master_shell_host_key_fingerprint"],
        })
    # Direct installation exists only for isolated tests.  Production always
    # crosses the root boundary through explicit local approval.
    if os.environ.get("LATTICE_PAIRING_TEST_DIRECT") == "1":
        _install_pairing_credentials(request)
        _write_worker_master_endpoint(
            normalized_master_ip, master_api_port, master_hostname
        )
        request["state"] = "paired"
        request["paired_at"] = _utc_now().isoformat()
        request.pop("master_public_key")
        request.pop("worker_token")
        _write_private_json(_state_path(), request)
        return {key: str(value) for key, value in request.items() if key in {"state", "hostname", "ssh_user", "master_hostname", "master_ip", "paired_at"}}

    _write_private_json(_state_path(), request)
    _make_lattice_owned_if_available(_state_path())
    return {
        "state": "awaiting_approval",
        "pairing_id": stored["pairing_id"],
        "hostname": stored["hostname"],
        "message": "Approve this pairing locally on the worker to continue.",
        "ssh_user": stored["ssh_user"],
        "worker_certificate": stored.get("worker_certificate", ""),
    }


def approve_worker_pairing(pairing_id: str) -> None:
    """Locally approve one exact pending pairing request.

    This must be run as root by the worker's local owner, normally using
    ``sudo lattice pairing approve``.  It deliberately does not accept any
    network supplied data on its command line.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", pairing_id):
        raise PairingError("Pairing ID has an invalid format")
    if os.geteuid() != 0:
        raise PairingError("Local approval requires sudo. Run: sudo lattice pairing approve")
    state = _load_state()
    if not state or state.get("state") != "awaiting_approval" or state.get("pairing_id") != pairing_id:
        raise PairingError("There is no matching pending pairing request")
    try:
        approval_expires_at = datetime.fromisoformat(state["approval_expires_at"])
        if approval_expires_at.tzinfo is None:
            raise ValueError("timezone is missing")
    except (KeyError, TypeError, ValueError) as exc:
        raise PairingError("Pending pairing request has an invalid expiration") from exc
    if approval_expires_at <= _utc_now():
        raise PairingError("Pending pairing request has expired")
    public_key = str(state.get("master_public_key", ""))
    approval_fields = {
        key: state.get(key)
        for key in (
            "pairing_id", "hostname", "ssh_user", "master_hostname", "master_ip",
            "master_public_key",
            "fleet_id",
            "master_node_id",
            "master_file_public_key",
            "master_file_host_public_key",
            "master_file_host_key_fingerprint",
            "master_shell_public_key",
            "master_shell_host_public_key",
            "master_shell_host_key_fingerprint",
            "fleet_signing_public_key",
            "worker_token",
            "master_ca_certificate",
            "master_api_port",
            "approval_expires_at",
        )
    }
    approval_digest = hashlib.sha256(
        json.dumps(approval_fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    helper = Path(os.environ.get("LATTICE_PAIRING_HELPER", DEFAULT_PAIRING_HELPER))
    if helper != DEFAULT_PAIRING_HELPER:
        raise PairingError("Production pairing helper path may not be overridden")
    try:
        result = subprocess.run(
            [str(helper), "--approve", pairing_id, approval_digest],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PairingError(f"Could not complete local approval: {exc}") from exc
    if result.returncode != 0:
        raise PairingError((result.stderr or result.stdout or "Local approval was refused").strip())
    try:
        from lattice.core.mdns import stop_broadcast
        stop_broadcast()
    except Exception as exc:
        # Pairing credentials are already installed. Discovery cleanup can be
        # retried safely without pretending the pairing itself failed.
        __import__("logging").getLogger(__name__).warning(
            "Pairing succeeded but waiting-worker discovery cleanup failed: %s", exc
        )


def get_paired_worker_identity() -> dict[str, Any]:
    """Return this paired Worker's canonical permanent public fleet identity.

    This is intended only for a token-authenticated local Worker API endpoint.
    It derives public material from the permanent identity/key files rather
    than retaining the original pre-pairing offer indefinitely.
    """
    state = _load_state()
    if not state or state.get("state") != "paired":
        raise PairingError("Worker is not paired")
    hostname = _validate_hostname(str(state.get("hostname", "")))
    main_user = str(state.get("ssh_user", ""))
    if not main_user:
        raise PairingError("Paired worker main user is unavailable")
    try:
        from lattice.file_access.profile import ensure_local_file_profile
        profile = ensure_local_file_profile(main_user)
    except Exception as exc:
        raise PairingError(f"Worker permanent identity is unavailable: {exc}") from exc
    recovery_ssh_host_public_key, recovery_ssh_host_key_fingerprint = (
        _recovery_ssh_host_identity()
    )
    return {
        "hostname": hostname,
        "node_id": profile.node_id,
        "main_user": profile.main_user,
        "main_uid": profile.main_uid,
        "main_gid": profile.main_gid,
        "file_public_key": profile.client.public_key_text,
        "file_host_public_key": profile.host.public_key_text,
        "file_host_key_fingerprint": profile.host.fingerprint,
        "file_key_generation": 1,
        "shell_public_key": profile.shell_client.public_key_text,
        "shell_host_public_key": profile.shell_host.public_key_text,
        "shell_host_key_fingerprint": profile.shell_host.fingerprint,
        "shell_key_generation": 1,
        "backup_public_key": profile.backup_client.public_key_text,
        "backup_host_public_key": profile.backup_host.public_key_text,
        "backup_host_key_fingerprint": profile.backup_host.fingerprint,
        "backup_key_generation": 1,
        "recovery_ssh_host_public_key": recovery_ssh_host_public_key,
        "recovery_ssh_host_key_fingerprint": recovery_ssh_host_key_fingerprint,
    }


def get_local_pending_pairing_details() -> dict[str, str] | None:
    """Return the request details that a person on the worker must verify."""
    # This also expires and scrubs stale pending requests.
    if get_public_pairing_status() is None:
        return None
    state = _load_state()
    if not state or state.get("state") != "awaiting_approval":
        return None
    public_key = str(state.get("master_public_key", ""))
    return {
        "pairing_id": str(state["pairing_id"]),
        "master_hostname": str(state["master_hostname"]),
        "master_ip": str(state["master_ip"]),
        "key_fingerprint": hashlib.sha256(public_key.encode("utf-8")).hexdigest()[:16],
    }


def save_master_worker_token(hostname: str, token: str) -> Path:
    """Store a paired worker token on the master using the existing token path."""
    return _write_worker_token(_validate_hostname(hostname), token)
