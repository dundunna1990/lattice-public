import os
import logging

logger = logging.getLogger(__name__)
import subprocess
from pathlib import Path
import grp
import pwd
DEFAULT_SSH_DIR = Path("/etc/lattice/keys")

def ensure_lattice_ssh_key(key_name: str = "lattice_ed25519", ssh_dir: Path = DEFAULT_SSH_DIR) -> tuple[Path, Path]:
    """
    Ensures that a dedicated Ed25519 SSH key pair exists for Lattice.
    Generates one non-interactively if it does not exist.
    """
    ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    private_key_path = ssh_dir / key_name
    public_key_path = ssh_dir / f"{key_name}.pub"

    if private_key_path.exists() != public_key_path.exists():
        raise RuntimeError(
            "Lattice SSH key pair is incomplete. Restore the missing matching key "
            "or deliberately remove both files before generating a new pair."
        )
    if not private_key_path.exists():
        logger.info("Generating new Ed25519 SSH key pair at %s", private_key_path)
        cmd = [
            "ssh-keygen",
            "-t", "ed25519",
            "-f", str(private_key_path),
            "-N", "",
            "-C", "lattice-cluster-key"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to generate SSH key: {result.stderr}")

    os.chmod(private_key_path, 0o600)
    os.chmod(public_key_path, 0o644)
    try:
        lattice_gid = grp.getgrnam("lattice").gr_gid
    except KeyError:
        # Source-tree development and isolated tests need not have the system
        # account. A real installation creates it before this code runs.
        lattice_gid = None
    if lattice_gid is not None and os.geteuid() == 0:
        # The master daemon runs as the dedicated lattice account and must be
        # able to use this client key for the pinned forced-SSH recovery path.
        # Keep it single-user readable so OpenSSH accepts it.
        try:
            lattice_uid = pwd.getpwnam("lattice").pw_uid
        except KeyError:
            lattice_uid = None
        if lattice_uid is not None:
            os.chown(private_key_path, lattice_uid, lattice_gid)
        os.chown(public_key_path, 0, lattice_gid)
        os.chmod(private_key_path, 0o600)

    return private_key_path, public_key_path

def install_restricted_authorized_key(
    public_key_path: Path,
    allowed_cidr: str,
    authorized_keys_path: Path = DEFAULT_SSH_DIR / "authorized_keys"
):
    if not public_key_path.exists():
        raise FileNotFoundError(f"Public key not found at {public_key_path}")

    pub_key_content = public_key_path.read_text().strip()
    install_restricted_authorized_key_text(pub_key_content, allowed_cidr, authorized_keys_path)


def install_restricted_authorized_key_text(
    public_key: str,
    allowed_cidr: str,
    authorized_keys_path: Path = DEFAULT_SSH_DIR / "authorized_keys",
):
    """Install an already-validated public key with Lattice SSH restrictions."""
    pub_key_content = public_key.strip()
    restrictions = f'from="{allowed_cidr}",no-pty,no-X11-forwarding,no-port-forwarding'
    restricted_entry = f"{restrictions} {pub_key_content}"

    authorized_keys_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    existing_lines = []
    if authorized_keys_path.exists():
        existing_lines = authorized_keys_path.read_text().splitlines()

    updated = False
    new_lines = []
    for line in existing_lines:
        if pub_key_content in line:
            new_lines.append(restricted_entry)
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(restricted_entry)

    authorized_keys_path.write_text("\n".join(new_lines) + "\n")
    os.chmod(authorized_keys_path, 0o600)
    logger.info("Successfully installed restricted authorized_key for CIDR: %s", allowed_cidr)
