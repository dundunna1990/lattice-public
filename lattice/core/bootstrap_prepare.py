"""lattice.core.bootstrap_prepare — one-shot prep for lattice-init.service."""
import logging
import os
import sys
from pathlib import Path
import grp
import pwd

from lattice.core.platform import require_supported_platform

logger = logging.getLogger(__name__)


def _account_ids() -> tuple[int, int]:
    """Return the installed daemon account ids, failing clearly if absent."""
    return pwd.getpwnam("lattice").pw_uid, grp.getgrnam("lattice").gr_gid


def _ensure_dir(path: Path, mode: int, uid: int, gid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _repair_runtime_files(uid: int, gid: int) -> None:
    """Repair daemon-owned shared state after root-run setup/reinstalls.

    Root-run pairing/setup can create files that the unprivileged daemon must
    reopen later. Normalize those exact known files before services start.
    """
    known_files = (
        (Path("/run/lattice/ip_monitor.lock"), 0o640),
        (Path("/run/lattice/mount-plans.lock"), 0o640),
        (Path("/var/lib/lattice/mount-plans.json"), 0o600),
    )
    for path, mode in known_files:
        if path.exists():
            os.chown(path, uid, gid)
            os.chmod(path, mode)


def ensure_dirs() -> None:
    """Create the fixed runtime layout with deliberate ownership boundaries."""
    lattice_uid, lattice_gid = _account_ids()
    root_dirs = (
        (Path("/etc/lattice"), 0o750, 0, lattice_gid),
        (Path("/etc/lattice/tokens"), 0o750, 0, lattice_gid),
        (Path("/etc/lattice/keys"), 0o750, 0, lattice_gid),
        (Path("/etc/lattice/pki"), 0o750, 0, lattice_gid),
        (Path("/etc/lattice/worker-certs"), 0o750, 0, lattice_gid),
        # Root-only wizard state must never share a parent with the
        # network-facing daemon account.
        (Path("/var/lib/lattice-root"), 0o700, 0, 0),
    )
    daemon_dirs = (
        (Path("/var/lib/lattice"), 0o750, lattice_uid, lattice_gid),
        (Path("/var/lib/lattice/tokens"), 0o700, lattice_uid, lattice_gid),
        (Path("/var/lib/lattice/keys"), 0o700, lattice_uid, lattice_gid),
        (Path("/var/log/lattice"), 0o750, lattice_uid, lattice_gid),
        (Path("/run/lattice"), 0o755, lattice_uid, lattice_gid),
    )
    for path, mode, uid, gid in root_dirs + daemon_dirs:
        _ensure_dir(path, mode, uid, gid)
    _repair_runtime_files(lattice_uid, lattice_gid)


def run_db_migrations() -> None:
    from lattice.core.migrations import run_migrations
    from lattice.core.db import get_db_connection
    from lattice.core.db_recovery import (
        DatabaseRecoveryError,
        create_verified_backup,
        database_path,
        verify_database,
    )

    db_path = database_path()

    if db_path.exists():
        if not verify_database(db_path):
            raise DatabaseRecoveryError(
                "Lattice database integrity check failed. "
                "The damaged database was left untouched. "
                "Restore an explicitly verified backup before retrying."
            )

        # Preserve one verified pre-migration restore point.
        create_verified_backup(db_path)

    conn = get_db_connection()
    try:
        run_migrations(conn)
        conn.commit()
    finally:
        conn.close()

    if not verify_database(db_path):
        raise DatabaseRecoveryError(
            "Lattice database failed integrity verification "
            "after migration"
        )
    db_path = Path(
        os.environ["LATTICE_DB_PATH"]
    ).resolve()
    runtime_root = Path(
        "/var/lib/lattice"
    ).resolve()
    if db_path.is_relative_to(runtime_root):
        lattice_uid, lattice_gid = _account_ids()
        for path in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
            if path.exists():
                os.chown(path, lattice_uid, lattice_gid)
                os.chmod(path, 0o640)


def validate_config() -> None:
    from lattice.core.config import load_config
    config = load_config()
    logger.info(f"Config loaded: master.ip={config.master.ip}")


def ensure_token_files() -> None:
    from lattice.core.config import load_config
    config = load_config()
    token = getattr(config.master, "api_token", None)
    if not token:
        logger.info("No api_token; skipping")
        return
    token_path = Path("/etc/lattice/tokens/master.token")
    if token_path.exists():
        return
    _ensure_dir(token_path.parent, 0o750, 0, _account_ids()[1])
    temporary_path = token_path.with_name(f".{token_path.name}.tmp")
    descriptor = os.open(temporary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(token)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary_path, 0, _account_ids()[1])
        os.chmod(temporary_path, 0o640)
        os.replace(temporary_path, token_path)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def ensure_ssh_keys() -> None:
    try:
        from lattice.core.crypto.ssh import ensure_lattice_ssh_key
        ensure_lattice_ssh_key()
    except Exception as e:
        logger.warning(f"ensure_lattice_ssh_key: {e}")


def ensure_encryption_identity() -> None:
    role_path = Path("/etc/lattice/role")
    if not role_path.exists():
        return
    role = role_path.read_text(encoding="utf-8").strip()
    from lattice.core.config import load_config
    from lattice.core.pki import ensure_master_identity, ensure_worker_identity
    if role == "master":
        ensure_master_identity(ip=load_config().master.ip)
    elif role == "worker":
        ensure_worker_identity()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [bootstrap] %(levelname)s %(message)s")
    for name, fn in [
        ("platform", require_supported_platform),
        ("ensure_dirs", ensure_dirs),
        ("db_migrations", run_db_migrations),
        ("validate_config", validate_config),
        ("ensure_token_files", ensure_token_files),
        ("ensure_ssh_keys", ensure_ssh_keys),
        ("ensure_encryption_identity", ensure_encryption_identity),
    ]:
        logger.info(f"-> {name}")
        try:
            fn()
        except Exception as e:
            logger.error(f"FAILED: {name}: {e}")
            sys.exit(1)
    logger.info("bootstrap_prepare complete.")


if __name__ == "__main__":
    main()
