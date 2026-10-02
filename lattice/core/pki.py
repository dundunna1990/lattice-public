"""Small private certificate authority used only by a Lattice installation."""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile


DEFAULT_PKI_DIR = Path("/etc/lattice/pki")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")


class PKIError(RuntimeError):
    pass


def tls_hostname(hostname: str) -> str:
    """Return the stable mDNS name used for certificate verification."""
    if not _NAME.fullmatch(hostname):
        raise PKIError("Node hostname is invalid")
    if hostname.lower().endswith(".local"):
        return hostname
    return f"{hostname}.local"


def pki_dir() -> Path:
    return Path(os.environ.get("LATTICE_PKI_DIR", DEFAULT_PKI_DIR))


def _run(command: list[str], input_text: str | None = None) -> None:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, input=input_text)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PKIError(f"Could not run OpenSSL: {exc}") from exc
    if result.returncode != 0:
        raise PKIError((result.stderr or result.stdout or "OpenSSL failed").strip())


def _secure(path: Path, mode: int) -> None:
    path.chmod(mode)
    if os.geteuid() == 0 and os.environ.get("LATTICE_PKI_DIR") is None:
        import grp
        gid = grp.getgrnam("lattice").gr_gid
        os.chown(path, 0, gid)


def _openssl_ok(command: list[str]) -> bool:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _certificate_is_valid(cert: Path) -> bool:
    """Require a parseable certificate that is currently valid."""
    return (
        cert.is_file()
        and _openssl_ok(
            [
                "openssl",
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-checkend",
                "0",
            ]
        )
    )


def _private_key_is_valid(key: Path) -> bool:
    return (
        key.is_file()
        and _openssl_ok(
            [
                "openssl",
                "pkey",
                "-in",
                str(key),
                "-noout",
            ]
        )
    )


def _public_key_bytes_from_key(key: Path) -> bytes | None:
    try:
        result = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(key),
                "-pubout",
                "-outform",
                "DER",
            ],
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _public_key_bytes_from_cert(cert: Path) -> bytes | None:
    try:
        first = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cert),
                "-pubkey",
                "-noout",
            ],
            capture_output=True,
            timeout=15,
        )
        if first.returncode != 0:
            return None

        second = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-outform",
                "DER",
            ],
            input=first.stdout,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if second.returncode != 0:
        return None

    return second.stdout


def _key_matches_certificate(
    key: Path,
    cert: Path,
) -> bool:
    key_pub = _public_key_bytes_from_key(key)
    cert_pub = _public_key_bytes_from_cert(cert)

    return (
        key_pub is not None
        and cert_pub is not None
        and key_pub == cert_pub
    )


def _certificate_signed_by(
    cert: Path,
    ca_cert: Path,
) -> bool:
    return _openssl_ok(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(ca_cert),
            str(cert),
        ]
    )


def _ca_identity_valid(
    ca_key: Path,
    ca_cert: Path,
) -> bool:
    return (
        _private_key_is_valid(ca_key)
        and _certificate_is_valid(ca_cert)
        and _key_matches_certificate(
            ca_key,
            ca_cert,
        )
    )


def _master_leaf_valid(
    key: Path,
    cert: Path,
    ca_cert: Path,
) -> bool:
    return (
        _private_key_is_valid(key)
        and _certificate_is_valid(cert)
        and _key_matches_certificate(key, cert)
        and _certificate_signed_by(
            cert,
            ca_cert,
        )
    )


def _generate_master_leaf(
    *,
    hostname: str,
    ip: str | None,
    directory: Path,
    ca_key: Path,
    ca_cert: Path,
    key: Path,
    csr: Path,
    cert: Path,
) -> None:
    # Leaf material is replaceable because the CA remains stable.
    for path in (key, csr, cert):
        path.unlink(missing_ok=True)

    _run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(key),
        ]
    )

    _run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(key),
            "-out",
            str(csr),
            "-subj",
            f"/CN={hostname}",
        ]
    )

    extension = (
        f"subjectAltName=DNS:{hostname},"
        f"DNS:{tls_hostname(hostname)},"
        "DNS:localhost,IP:127.0.0.1"
    )

    if ip:
        extension += (
            f",IP:{ipaddress.ip_address(ip)}"
        )

    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(cert),
            "-days",
            "825",
            "-extfile",
            "/dev/stdin",
        ],
        input_text=extension,
    )


def ensure_master_identity(
    hostname: str | None = None,
    ip: str | None = None,
) -> dict[str, Path]:
    """Create or validate the installation CA and master TLS leaf.

    CA rotation is never automatic. Losing only one CA component is a
    recovery condition because replacing it would invalidate every paired
    worker. A valid intact CA may safely issue a replacement master leaf.
    """
    hostname = hostname or socket.gethostname()

    if not _NAME.fullmatch(hostname):
        raise PKIError("Master hostname is invalid")

    directory = pki_dir()
    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )

    ca_key = directory / "ca.key"
    ca_cert = directory / "ca.crt"
    key = directory / "master.key"
    csr = directory / "master.csr"
    cert = directory / "master.crt"

    ca_key_exists = ca_key.exists()
    ca_cert_exists = ca_cert.exists()

    if ca_key_exists != ca_cert_exists:
        raise PKIError(
            "Lattice CA identity is incomplete. "
            "Automatic CA regeneration was refused because it "
            "would invalidate existing paired workers. Restore "
            "the missing CA file or perform an explicit CA rotation."
        )

    if not ca_key_exists:
        _run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(ca_key),
            ]
        )
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-key",
                str(ca_key),
                "-out",
                str(ca_cert),
                "-days",
                "3650",
                "-subj",
                "/CN=Lattice Private CA",
            ]
        )

    if not _ca_identity_valid(
        ca_key,
        ca_cert,
    ):
        raise PKIError(
            "Lattice CA identity is invalid or expired. "
            "Automatic CA replacement was refused because it "
            "would invalidate existing paired workers."
        )

    if not _master_leaf_valid(
        key,
        cert,
        ca_cert,
    ):
        _generate_master_leaf(
            hostname=hostname,
            ip=ip,
            directory=directory,
            ca_key=ca_key,
            ca_cert=ca_cert,
            key=key,
            csr=csr,
            cert=cert,
        )

    if not _master_leaf_valid(
        key,
        cert,
        ca_cert,
    ):
        raise PKIError(
            "Master TLS identity could not be created or validated"
        )

    for path in (ca_key, key):
        _secure(path, 0o640)

    for path in (ca_cert, cert):
        _secure(path, 0o644)

    csr.unlink(missing_ok=True)

    return {
        "ca": ca_cert,
        "cert": cert,
        "key": key,
    }


def ensure_worker_csr(hostname: str | None = None) -> str:
    hostname = hostname or socket.gethostname()
    if not _NAME.fullmatch(hostname):
        raise PKIError("Worker hostname is invalid")
    directory = pki_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    key, csr = directory / "worker.key", directory / "worker.csr"
    if not key.exists():
        _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)])
        _secure(key, 0o640)
    if not csr.exists():
        _run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr), "-subj", f"/CN={hostname}"])
        _secure(csr, 0o644)
    return csr.read_text(encoding="utf-8")


def ensure_worker_identity(
    hostname: str | None = None,
    ip: str | None = None,
) -> dict[str, Path]:
    """Create a bootstrap worker identity or validate the existing pair.

    Once a worker identity exists, silently replacing only one component could
    break an established pairing. Existing partial/corrupt identities therefore
    fail closed and require explicit recovery.
    """
    hostname = hostname or socket.gethostname()

    if not _NAME.fullmatch(hostname):
        raise PKIError("Worker hostname is invalid")

    directory = pki_dir()
    directory.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )

    key = directory / "worker.key"
    cert = directory / "worker.crt"

    key_exists = key.exists()
    cert_exists = cert.exists()

    if key_exists != cert_exists:
        raise PKIError(
            "Worker TLS identity is incomplete. "
            "Automatic replacement was refused because it may "
            "break an existing pairing."
        )

    if not key_exists:
        _run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(key),
            ]
        )

        extension = (
            f"subjectAltName=DNS:{hostname},"
            f"DNS:{tls_hostname(hostname)}"
        )

        if ip:
            extension += (
                f",IP:{ipaddress.ip_address(ip)}"
            )

        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-key",
                str(key),
                "-out",
                str(cert),
                "-days",
                "825",
                "-subj",
                f"/CN={hostname}",
                "-addext",
                extension,
            ]
        )

    if not (
        _private_key_is_valid(key)
        and _certificate_is_valid(cert)
        and _key_matches_certificate(
            key,
            cert,
        )
    ):
        raise PKIError(
            "Worker TLS identity is invalid or expired. "
            "Automatic identity rotation was refused because it "
            "may break the existing pairing."
        )

    _secure(key, 0o640)
    _secure(cert, 0o644)

    return {
        "cert": cert,
        "key": key,
    }


def sign_worker_csr(csr_pem: str, hostname: str, ip: str) -> tuple[str, str]:
    """Sign a worker-created key request without ever receiving its private key."""
    identity = ensure_master_identity(ip=ip)
    directory = pki_dir()
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        request = Path(temporary) / "worker.csr"
        certificate = Path(temporary) / "worker.crt"
        request.write_text(csr_pem, encoding="utf-8")
        extension = (
            f"subjectAltName=DNS:{hostname},DNS:{tls_hostname(hostname)},"
            f"IP:{ipaddress.ip_address(ip)}"
        )
        _run(["openssl", "x509", "-req", "-in", str(request), "-CA", str(identity["ca"]), "-CAkey", str(directory / "ca.key"), "-CAcreateserial", "-out", str(certificate), "-days", "825", "-extfile", "/dev/stdin"], input_text=extension)
        return certificate.read_text(encoding="utf-8"), identity["ca"].read_text(encoding="utf-8")


def tls_client_options() -> dict:
    directory = pki_dir()
    return {"verify": str(directory / "ca.crt"), "cert": (str(directory / "master.crt"), str(directory / "master.key"))}


def tls_server_options(role: str) -> dict:
    if role not in {"master", "worker"}:
        raise PKIError(
            f"Unknown TLS server role: {role}"
        )

    directory = pki_dir()
    cert = directory / f"{role}.crt"
    key = directory / f"{role}.key"

    if not cert.exists() or not key.exists():
        raise PKIError(
            f"{role} TLS identity is missing; "
            "run lattice-init before starting the daemon"
        )

    if not (
        _private_key_is_valid(key)
        and _certificate_is_valid(cert)
        and _key_matches_certificate(
            key,
            cert,
        )
    ):
        raise PKIError(
            f"{role} TLS identity is invalid or expired"
        )

    return {
        "ssl_certfile": str(cert),
        "ssl_keyfile": str(key),
    }
