#!/bin/bash
# Modern Lattice bootstrap: install the current release, then launch setup.
# Run from the repository with: sudo ./lattice-bootstrap.sh
set -euo pipefail

# Prevent sudo-run setup from leaving root-owned __pycache__ files in the source checkout.
export PYTHONDONTWRITEBYTECODE=1

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run this bootstrap with sudo." >&2
    echo "Usage: sudo ./lattice-bootstrap.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLER="$SCRIPT_DIR/deploy/install.sh"

if [[ ! -x "$INSTALLER" ]]; then
    echo "ERROR: Lattice installer is missing: $INSTALLER" >&2
    exit 1
fi

if [[ -z "${SUDO_USER:-}" || "${SUDO_USER:-}" == "root" ]]; then
    echo "ERROR: run sudo from the normal human account that will use Lattice." >&2
    exit 1
fi

echo "==> Installing the current Lattice release..."
LATTICE_REPO_DIR="$SCRIPT_DIR" "$INSTALLER"

echo ""
echo "==> Installation complete. Starting guided setup..."
exec /usr/local/bin/lattice init
