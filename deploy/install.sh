#!/bin/bash
# Lattice full installer: system packages + Python deps + systemd + user + sudoers.
# Idempotent. Requires root. Version 1 supports Ubuntu and Linux Mint only.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: install.sh must be run as root (use sudo)" >&2
    exit 1
fi

if [[ ! -r /etc/os-release ]]; then
    echo "ERROR: cannot identify this operating system." >&2
    exit 1
fi
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "linuxmint" ]]; then
    echo "ERROR: Lattice version 1 supports only Ubuntu or Linux Mint with NetworkManager." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=host-state.sh
source "$SCRIPT_DIR/host-state.sh"
REPO_DIR="${LATTICE_REPO_DIR:-$SCRIPT_DIR/..}"
INSTALL_ROOT="/opt/lattice"
RELEASES_ROOT="/opt/lattice-releases"
RELEASE_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RELEASE_ROOT="$RELEASES_ROOT/$RELEASE_ID"
VENV_DIR="$RELEASE_ROOT/venv"
ACTIVE_VENV="$INSTALL_ROOT/venv"
LATTICE_USER="lattice"
LATTICE_GROUP="lattice"
OPERATOR_GROUP="lattice-operator"
CLI_LAUNCHER="/usr/local/bin/lattice"
HAD_EXISTING_INSTALL=0
OPERATOR_MEMBERSHIP_ADDED=0
RUNTIME_SERVICES=(
    lattice-file-sshd.service
    lattice-shell-sshd.service
    lattice-master.service
    lattice-worker.service
    lattice-mount-manager.service
    lattice-shell-connection-manager.service
)
if [[ -e "$INSTALL_ROOT" || -L "$INSTALL_ROOT" ]]; then
    HAD_EXISTING_INSTALL=1
fi
LATTICE_APT_PACKAGES=(
    python3 python3-venv python3-pip
    avahi-utils avahi-daemon
    sudo openssh-client openssh-server sshfs fuse3
    iproute2 iputils-ping arping iptables
    dbus ca-certificates openssl rsync curl bzip2 network-manager xdg-utils ufw libglib2.0-bin
)

RESTIC_VERSION="0.19.1"
RESTIC_SHA256_AMD64="f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"
RESTIC_SHA256_ARM64="a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465"

stage_restic() {
    local arch upstream_arch expected filename url archive destination actual
    arch="$(dpkg --print-architecture)"
    case "$arch" in
        amd64) upstream_arch="amd64"; expected="$RESTIC_SHA256_AMD64" ;;
        arm64) upstream_arch="arm64"; expected="$RESTIC_SHA256_ARM64" ;;
        *)
            echo "ERROR: Lattice Backup does not yet provide a pinned Restic build for architecture: $arch" >&2
            return 1
            ;;
    esac
    filename="restic_${RESTIC_VERSION}_linux_${upstream_arch}.bz2"
    url="https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/${filename}"
    install -d -m 0755 "$RELEASE_ROOT/bin"
    archive="$RELEASE_ROOT/.restic-${RESTIC_VERSION}-${upstream_arch}.bz2"
    destination="$RELEASE_ROOT/bin/restic"
    rm -f -- "$archive" "$destination"
    curl --fail --location --silent --show-error \
        --proto '=https' --tlsv1.2 \
        --output "$archive" "$url"
    actual="$(sha256sum "$archive" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        echo "ERROR: Restic ${RESTIC_VERSION} checksum verification failed." >&2
        return 1
    fi
    bzip2 -dc -- "$archive" > "$destination"
    chown root:"$LATTICE_GROUP" "$destination"
    chmod 0755 "$destination"
    if ! "$destination" version | grep -Fq "restic ${RESTIC_VERSION} "; then
        echo "ERROR: staged Restic binary did not report version ${RESTIC_VERSION}." >&2
        return 1
    fi
    rm -f -- "$archive"
    echo "  Restic: ${RESTIC_VERSION} (${arch}, SHA-256 verified)"
}

cleanup_legacy_user_cli_launcher() {
    local sudo_user="${SUDO_USER:-}"
    local user_home legacy

    if [[ -z "$sudo_user" || "$sudo_user" == "root" ]]; then
        return
    fi

    user_home="$(getent passwd "$sudo_user" | cut -d: -f6)"
    [[ -n "$user_home" ]] || return
    legacy="$user_home/.local/bin/lattice"

    if [[ -f "$legacy" && ! -L "$legacy" \
          && "$(stat -c '%U' "$legacy" 2>/dev/null || true)" == "$sudo_user" \
          && "$(wc -c < "$legacy" 2>/dev/null || echo 0)" -lt 4096 \
          && "$(grep -c '^from lattice\.cli\.main import main$' "$legacy" 2>/dev/null || true)" -eq 1 \
          && "$(grep -c 'sys\.exit(main())' "$legacy" 2>/dev/null || true)" -eq 1 ]]; then
        rm -f -- "$legacy"
        echo "  removed legacy user launcher: $legacy"
    fi
}

preflight_cli_launcher() {
    if [[ -e "$CLI_LAUNCHER" || -L "$CLI_LAUNCHER" ]]; then
        if [[ ! -L "$CLI_LAUNCHER" \
              || "$(readlink "$CLI_LAUNCHER" 2>/dev/null || true)" != "$ACTIVE_VENV/bin/lattice" ]]; then
            echo "ERROR: $CLI_LAUNCHER already exists and is not managed by Lattice." >&2
            return 1
        fi
    fi
}

preflight_cli_launcher
cleanup_legacy_user_cli_launcher

ACTIVATED=0
PREVIOUS_LINK=""
PREVIOUS_DIRECTORY=""
ROLLBACK_SNAPSHOT=""
SNAPSHOT_READY=0

snapshot_one() {
    local path="$1"
    local destination

    destination="$ROLLBACK_SNAPSHOT/files$path"
    mkdir -p "$(dirname "$destination")"

    if [[ -e "$path" || -L "$path" ]]; then
        cp -a -- "$path" "$destination"
    else
        : > "${destination}.__missing__"
    fi
}

restore_one() {
    local path="$1"
    local source

    source="$ROLLBACK_SNAPSHOT/files$path"

    rm -f -- "$path"

    if [[ -e "$source" || -L "$source" ]]; then
        mkdir -p "$(dirname "$path")"
        cp -a -- "$source" "$path"
    fi
}

snapshot_install_integration() {
    ROLLBACK_SNAPSHOT="$(
        mktemp -d /var/tmp/lattice-install-rollback.XXXXXX
    )"

    mkdir -p         "$ROLLBACK_SNAPSHOT/files"         "$ROLLBACK_SNAPSHOT/systemd"

    for path in         /etc/lattice/environment         /etc/lattice/lattice.toml         /etc/tmpfiles.d/lattice.conf         /etc/sysusers.d/lattice.conf         /etc/sudoers.d/lattice-action-exec         /etc/logrotate.d/lattice         /usr/local/bin/lattice         /usr/share/applications/lattice.desktop         /usr/share/applications/lattice-nodes.desktop         /usr/share/pixmaps/lattice.png         /usr/share/pixmaps/lattice-nodes.png         /usr/share/icons/hicolor/256x256/apps/lattice.png         /usr/share/icons/hicolor/scalable/apps/lattice.svg
    do
        snapshot_one "$path"
    done

    while IFS= read -r -d '' unit; do
        cp -a --             "$unit"             "$ROLLBACK_SNAPSHOT/systemd/"
    done < <(
        find /etc/systemd/system             -maxdepth 1             \( -type f -o -type l \)             -name 'lattice-*'             -print0
    )

    SNAPSHOT_READY=1
}

restore_install_integration() {
    if [[ "$SNAPSHOT_READY" -ne 1 ]]; then
        return
    fi

    for path in         /etc/lattice/environment         /etc/lattice/lattice.toml         /etc/tmpfiles.d/lattice.conf         /etc/sysusers.d/lattice.conf         /etc/sudoers.d/lattice-action-exec         /etc/logrotate.d/lattice         /usr/local/bin/lattice         /usr/share/applications/lattice.desktop         /usr/share/applications/lattice-nodes.desktop         /usr/share/pixmaps/lattice.png         /usr/share/pixmaps/lattice-nodes.png         /usr/share/icons/hicolor/256x256/apps/lattice.png         /usr/share/icons/hicolor/scalable/apps/lattice.svg
    do
        restore_one "$path"
    done

    find /etc/systemd/system         -maxdepth 1         \( -type f -o -type l \)         -name 'lattice-*'         -delete

    if compgen -G         "$ROLLBACK_SNAPSHOT/systemd/lattice-*"         >/dev/null
    then
        cp -a             "$ROLLBACK_SNAPSHOT/systemd/"lattice-*             /etc/systemd/system/
    fi

    systemctl daemon-reload         >/dev/null 2>&1 || true
}

cleanup_install_snapshot() {
    if [[ -n "$ROLLBACK_SNAPSHOT" ]]; then
        rm -rf -- "$ROLLBACK_SNAPSHOT"
    fi
}

rollback_install() {
    local status="${1:-1}"

    # Never recurse if a rollback command itself fails.
    trap - ERR INT TERM
    set +e

    if [[ "$ACTIVATED" -eq 1 ]]; then
        echo             "ERROR: install failed after activation; restoring previous release"             >&2

        rm -f "$INSTALL_ROOT"

        if [[ -n "$PREVIOUS_LINK" ]]; then
            ln -s                 "$PREVIOUS_LINK"                 "$INSTALL_ROOT"
        elif [[             -n "$PREVIOUS_DIRECTORY"             && -e "$PREVIOUS_DIRECTORY"         ]]; then
            mv                 "$PREVIOUS_DIRECTORY"                 "$INSTALL_ROOT"
        fi
    fi

    restore_install_integration

    if [[ "$ACTIVATED" -eq 1 && "$HAD_EXISTING_INSTALL" -eq 1 ]]; then
        for unit in "${RUNTIME_SERVICES[@]}"; do
            systemctl try-restart "$unit" >/dev/null 2>&1 || true
        done
    fi

    # The failed candidate release is never kept as an installed artifact.
    if [[ -d "$RELEASE_ROOT" ]]; then
        rm -rf -- "$RELEASE_ROOT"
    fi

    cleanup_install_snapshot

    if [[ "${HOST_STATE_CREATED_THIS_INSTALL:-0}" -eq 1 ]]; then
        echo "==> Restoring pre-Lattice host state after failed first install..." >&2
        # Installer-created identities are safe to remove only when their
        # root-private ownership markers say this attempt created them.
        if [[ -f /var/lib/lattice-root/managed-operator-members ]]; then
            while IFS= read -r member; do
                [[ "$member" =~ ^[A-Za-z0-9._-]+$ ]] || continue
                getent group lattice-operator >/dev/null && gpasswd -d "$member" lattice-operator >/dev/null 2>&1 || true
            done < /var/lib/lattice-root/managed-operator-members
        fi
        if [[ -f /var/lib/lattice-root/managed-user-lattice ]] && id lattice >/dev/null 2>&1; then
            pkill -u lattice >/dev/null 2>&1 || true
            userdel lattice >/dev/null 2>&1 || true
        fi
        if [[ -f /var/lib/lattice-root/managed-group-lattice ]] && getent group lattice >/dev/null; then
            groupdel lattice >/dev/null 2>&1 || true
        fi
        if [[ -f /var/lib/lattice-root/managed-group-lattice-operator ]] && getent group lattice-operator >/dev/null; then
            groupdel lattice-operator >/dev/null 2>&1 || true
        fi
        HOST_STATE_ROLLBACK_OK=true
        if ! lattice_host_state_restore; then
            HOST_STATE_ROLLBACK_OK=false
            echo "WARNING: exact pre-Lattice host restoration was incomplete; preserving /var/lib/lattice-root for diagnosis." >&2
        fi
        rm -rf /etc/lattice /var/lib/lattice /var/log/lattice /run/lattice /run/lattice-operator
        if [[ "$HOST_STATE_ROLLBACK_OK" == "true" ]]; then
            rm -rf /var/lib/lattice-root
        fi
        rmdir /opt/lattice-releases >/dev/null 2>&1 || true
    fi

    exit "$status"
}

trap 'rollback_install $?' ERR
trap 'rollback_install 130' INT
trap 'rollback_install 143' TERM

snapshot_install_integration
lattice_host_state_snapshot

echo "==> Lattice installer"
echo "    REPO:         $REPO_DIR"
echo "    INSTALL:      $INSTALL_ROOT"
echo "    LATTICE_USER: $LATTICE_USER"
echo ""

# 1. System packages
if [[ -v LATTICE_INSTALL_ROOT && "$LATTICE_INSTALL_ROOT" != "$INSTALL_ROOT" ]]; then
    echo "ERROR: custom install roots are not supported yet; use $INSTALL_ROOT." >&2
    exit 1
fi

echo "==> [1/7] Installing system packages..."
if command -v apt-get &>/dev/null; then
    echo "  detected: apt"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    lattice_host_state_plan_packages "${LATTICE_APT_PACKAGES[@]}"
    DEBIAN_FRONTEND=noninteractive apt-get install --no-upgrade -y -qq -- \
        "${LATTICE_APT_PACKAGES[@]}"
else
    echo "ERROR: apt is required on supported Ubuntu/Linux Mint systems." >&2
    exit 1
fi
command -v nmcli >/dev/null || { echo "ERROR: NetworkManager was not installed correctly." >&2; exit 1; }
lattice_host_state_finalize_packages

# 2. Lattice user
echo ""
echo "==> [2/7] Ensuring lattice user exists..."
# Minimal supported systems do not necessarily pre-create every /etc integration
# directory. Create every parent Lattice writes into before the first copy.
install -d -m 0755 /etc/sysusers.d /etc/tmpfiles.d /etc/systemd/system
install -d -m 0750 /etc/sudoers.d

# Record only accounts and memberships that Lattice itself creates.
# The uninstaller uses these root-private markers so --purge never
# deletes a pre-existing administrator account or group by accident.
MANAGED_ACCOUNT_ROOT="/var/lib/lattice-root"
install -d -m 0700 -o root -g root "$MANAGED_ACCOUNT_ROOT"

LATTICE_GROUP_PREEXISTED=false
if getent group "$LATTICE_GROUP" >/dev/null; then
    LATTICE_GROUP_PREEXISTED=true
fi

OPERATOR_GROUP_PREEXISTED=false
if getent group "$OPERATOR_GROUP" >/dev/null; then
    OPERATOR_GROUP_PREEXISTED=true
fi

if ! id "$LATTICE_USER" &>/dev/null; then
    if [[ -f "$SCRIPT_DIR/sysusers.d/lattice.conf" ]]; then
        install -m 0644 "$SCRIPT_DIR/sysusers.d/lattice.conf" /etc/sysusers.d/lattice.conf
        systemd-sysusers
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$LATTICE_USER"
    fi
    echo "  created user: $LATTICE_USER"

    touch "$MANAGED_ACCOUNT_ROOT/managed-user-lattice"
    chmod 0600 "$MANAGED_ACCOUNT_ROOT/managed-user-lattice"

    if [[ "$LATTICE_GROUP_PREEXISTED" == "false" ]] \
       && getent group "$LATTICE_GROUP" >/dev/null; then
        touch "$MANAGED_ACCOUNT_ROOT/managed-group-lattice"
        chmod 0600 "$MANAGED_ACCOUNT_ROOT/managed-group-lattice"
    fi
else
    echo "  user $LATTICE_USER already exists"
fi
if ! getent group "$OPERATOR_GROUP" >/dev/null; then
    groupadd --system "$OPERATOR_GROUP"
    echo "  created group: $OPERATOR_GROUP"
fi

# systemd-sysusers may have created lattice-operator while creating the
# lattice service account. Record ownership regardless of which creation
# path produced the group.
if [[ "$OPERATOR_GROUP_PREEXISTED" == "false" ]] \
   && getent group "$OPERATOR_GROUP" >/dev/null; then
    touch "$MANAGED_ACCOUNT_ROOT/managed-group-lattice-operator"
    chmod 0600 "$MANAGED_ACCOUNT_ROOT/managed-group-lattice-operator"
fi

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    if ! id -nG "$SUDO_USER" | tr ' ' '\n' | grep -Fxq "$OPERATOR_GROUP"; then
        usermod -a -G "$OPERATOR_GROUP" "$SUDO_USER"
        OPERATOR_MEMBERSHIP_ADDED=1

        MEMBERS_FILE="$MANAGED_ACCOUNT_ROOT/managed-operator-members"
        touch "$MEMBERS_FILE"
        chmod 0600 "$MEMBERS_FILE"

        if ! grep -Fxq "$SUDO_USER" "$MEMBERS_FILE"; then
            printf '%s\n' "$SUDO_USER" >> "$MEMBERS_FILE"
        fi

        echo "  operator access enabled for: $SUDO_USER"
    else
        echo "  operator access already present for: $SUDO_USER"
    fi
fi

# 3. Runtime dirs
echo ""
echo "==> [3/7] Setting up runtime directories..."
install -d -m 0750 -o "$LATTICE_USER" -g "$LATTICE_GROUP" /var/lib/lattice
install -d -m 0750 -o "$LATTICE_USER" -g "$LATTICE_GROUP" /var/log/lattice
install -d -m 0755 -o "$LATTICE_USER" -g "$LATTICE_GROUP" /run/lattice
install -d -m 2770 -o "$LATTICE_USER" -g "$OPERATOR_GROUP" /run/lattice-operator
install -d -m 0750 -o root -g "$LATTICE_GROUP" /etc/lattice
install -d -m 0750 -o root -g "$LATTICE_GROUP" /etc/lattice/tokens
install -d -m 0750 -o root -g "$LATTICE_GROUP" /etc/lattice/keys
# Recovery SSH is initiated by the unprivileged master daemon. Preserve
# OpenSSH-safe 0600 permissions while making an existing client key usable
# by that dedicated service account.
if [[ -f /etc/lattice/keys/lattice_ed25519 ]]; then
    chown "$LATTICE_USER:$LATTICE_GROUP" /etc/lattice/keys/lattice_ed25519
    chmod 0600 /etc/lattice/keys/lattice_ed25519
fi
install -d -m 0700 -o root -g root /etc/lattice/file-ssh
install -d -m 0700 -o root -g root /etc/lattice/shell-ssh
install -d -m 0750 -o root -g "$LATTICE_GROUP" /etc/lattice/backup-ssh
install -d -m 0700 -o root -g root /etc/lattice/backup
install -d -m 0700 -o root -g root /etc/lattice/backup/credentials
install -d -m 0700 -o root -g root /var/lib/lattice-root
install -d -m 0700 -o root -g root /var/lib/lattice-root/restic-cache
install -m 0640 -o root -g "$LATTICE_GROUP" \
    "$SCRIPT_DIR/lattice.environment" /etc/lattice/environment
if [[ -f /etc/lattice/lattice.toml ]]; then
    chown root:"$LATTICE_GROUP" /etc/lattice/lattice.toml
    chmod 0640 /etc/lattice/lattice.toml
fi
if [[ -f "$SCRIPT_DIR/tmpfiles.d/lattice.conf" ]]; then
    install -m 0644 "$SCRIPT_DIR/tmpfiles.d/lattice.conf" /etc/tmpfiles.d/lattice.conf
    systemd-tmpfiles --create lattice.conf 2>/dev/null || true
fi

# 4. Stage code in a permanent versioned release directory
echo ""
echo "==> [4/7] Staging Lattice release $RELEASE_ID..."
install -d -m 0755 "$RELEASES_ROOT"
install -d -m 0755 "$RELEASE_ROOT"

if [[ -d "$REPO_DIR/.git" ]]; then
    command -v git >/dev/null || {
        echo "ERROR: Git is required to stage a Git checkout safely." >&2
        exit 1
    }
    if [[ -n "$(git -C "$REPO_DIR" ls-files --deleted)" ]]; then
        echo "ERROR: tracked files are missing from the working tree; stage or restore the deletion before installing." >&2
        exit 1
    fi
    git -C "$REPO_DIR" ls-files -z --cached |
        rsync -a --from0 --files-from=- "$REPO_DIR/" "$RELEASE_ROOT/"
else
    rsync -a --delete \
        --exclude='venv/' --exclude='.venv/' --exclude='.test-venv/' \
        --exclude='__pycache__/' --exclude='*.pyc' --exclude='.pytest_cache/' \
        --exclude='lattice.db*' --exclude='.mypy_cache/' --exclude='.ruff_cache/' \
        --exclude='docs/archive/' "$REPO_DIR/" "$RELEASE_ROOT/"
fi

chown -R root:"$LATTICE_GROUP" "$RELEASE_ROOT"

find "$RELEASE_ROOT" -type d -exec chmod 0755 {} \;
find "$RELEASE_ROOT" -type f -exec chmod 0644 {} \;

stage_restic

echo "  staged: $RELEASE_ROOT"

# 5. Build and verify the staged venv BEFORE changing /opt/lattice
echo ""
echo "==> [5/7] Building and validating staged release..."

for lock in requirements-build.lock requirements.lock; do
    [[ -f "$RELEASE_ROOT/$lock" ]] || {
        echo "ERROR: missing staged $lock" >&2
        false
    }
done

python3 -m venv "$VENV_DIR"

"$VENV_DIR/bin/pip" install \
    --require-hashes \
    -r "$RELEASE_ROOT/requirements-build.lock" \
    --quiet

"$VENV_DIR/bin/pip" install \
    --require-hashes \
    -r "$RELEASE_ROOT/requirements.lock" \
    --quiet

"$VENV_DIR/bin/pip" install \
    --no-deps \
    --no-build-isolation \
    "$RELEASE_ROOT" \
    --quiet

"$VENV_DIR/bin/python" -m compileall -q "$RELEASE_ROOT/lattice"
"$VENV_DIR/bin/python" -c 'import lattice'
"$VENV_DIR/bin/lattice" --version

echo "  staged release validated"

# Activate only after the complete release and venv have passed validation.
echo "==> Activating staged release atomically..."

if [[ -L "$INSTALL_ROOT" ]]; then
    PREVIOUS_LINK="$(readlink -f "$INSTALL_ROOT")"
elif [[ -e "$INSTALL_ROOT" ]]; then
    PREVIOUS_DIRECTORY="$RELEASES_ROOT/legacy-$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mv "$INSTALL_ROOT" "$PREVIOUS_DIRECTORY"
fi

TEMP_LINK="${INSTALL_ROOT}.new.$$"
ln -s "$RELEASE_ROOT" "$TEMP_LINK"
mv -Tf "$TEMP_LINK" "$INSTALL_ROOT"

ACTIVATED=1

echo "  active: $INSTALL_ROOT -> $RELEASE_ROOT"

# Expose one stable operator command without copying code out of the active
# release. The preflight above already proved any existing path is ours.
install -d -m 0755 /usr/local/bin
CLI_TEMP="${CLI_LAUNCHER}.new.$$"
ln -s "$ACTIVE_VENV/bin/lattice" "$CLI_TEMP"
mv -Tf "$CLI_TEMP" "$CLI_LAUNCHER"
chown -h root:root "$CLI_LAUNCHER"

# 6. action-exec + sudoers
echo ""
echo "==> [6/7] Installing privileged helpers and narrow sudoers rule..."
# Remove legacy broad passwordless-sudo files created by pre-hardening
# `lattice bootstrap`. Modern Lattice uses only exact root-owned helpers.
find /etc/sudoers.d -maxdepth 1 -type f -name 'lattice-*-nopasswd' -delete
install -d -m 0755 "$INSTALL_ROOT/bin"
if [[ -f "$SCRIPT_DIR/lattice-action-exec" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-action-exec" "$INSTALL_ROOT/bin/lattice-action-exec"
    chown root:"$LATTICE_GROUP" "$INSTALL_ROOT/bin/lattice-action-exec"
fi
if [[ -f "$SCRIPT_DIR/lattice-ssh-command" ]]; then
    install -m 0755 "$SCRIPT_DIR/lattice-ssh-command" "$INSTALL_ROOT/bin/lattice-ssh-command"
    chown root:root "$INSTALL_ROOT/bin/lattice-ssh-command"
fi
if [[ -f "$SCRIPT_DIR/lattice-pairing-exec" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-pairing-exec" "$INSTALL_ROOT/bin/lattice-pairing-exec"
    chown root:"$LATTICE_GROUP" "$INSTALL_ROOT/bin/lattice-pairing-exec"
fi
if [[ -f "$SCRIPT_DIR/lattice-recovery-auth-exec" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-recovery-auth-exec" "$INSTALL_ROOT/bin/lattice-recovery-auth-exec"
    chown root:root "$INSTALL_ROOT/bin/lattice-recovery-auth-exec"
fi
if [[ -f "$SCRIPT_DIR/lattice-network-exec" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-network-exec" "$INSTALL_ROOT/bin/lattice-network-exec"
    chown root:"$LATTICE_GROUP" "$INSTALL_ROOT/bin/lattice-network-exec"
fi
if [[ -f "$SCRIPT_DIR/lattice-file-transport-exec" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-file-transport-exec" "$INSTALL_ROOT/bin/lattice-file-transport-exec"
    chown root:"$LATTICE_GROUP" "$INSTALL_ROOT/bin/lattice-file-transport-exec"
fi
if [[ -f "$SCRIPT_DIR/lattice-backup-transport-exec" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-backup-transport-exec" "$INSTALL_ROOT/bin/lattice-backup-transport-exec"
    chown root:"$LATTICE_GROUP" "$INSTALL_ROOT/bin/lattice-backup-transport-exec"
fi
if [[ -f "$SCRIPT_DIR/lattice-backup-control" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-backup-control" "$INSTALL_ROOT/bin/lattice-backup-control"
    chown root:"$OPERATOR_GROUP" "$INSTALL_ROOT/bin/lattice-backup-control"
fi
if [[ -f "$SCRIPT_DIR/lattice-care-control" ]]; then
    install -m 0750 "$SCRIPT_DIR/lattice-care-control" "$INSTALL_ROOT/bin/lattice-care-control"
    chown root:"$OPERATOR_GROUP" "$INSTALL_ROOT/bin/lattice-care-control"
fi
if [[ -f "$SCRIPT_DIR/lattice-desktop-open" ]]; then
    install -m 0755 "$SCRIPT_DIR/lattice-desktop-open" "$INSTALL_ROOT/bin/lattice-desktop-open"
    chown root:root "$INSTALL_ROOT/bin/lattice-desktop-open"
fi

if [[ ! -f "$SCRIPT_DIR/lattice-tui-open" ]]; then
    echo "ERROR: required Lattice TUI desktop launcher is missing." >&2
    exit 1
fi
install -m 0755 "$SCRIPT_DIR/lattice-tui-open" "$INSTALL_ROOT/bin/lattice-tui-open"
chown root:root "$INSTALL_ROOT/bin/lattice-tui-open"

install -d -m 0755 /usr/share/applications

install -m 0644 "$SCRIPT_DIR/applications/lattice.desktop"     /usr/share/applications/lattice.desktop
chown root:root /usr/share/applications/lattice.desktop

install -m 0644 "$SCRIPT_DIR/applications/lattice-nodes.desktop"     /usr/share/applications/lattice-nodes.desktop
chown root:root /usr/share/applications/lattice-nodes.desktop

if [[ ! -f "$SCRIPT_DIR/icons/lattice-app.png" ]]; then
    echo "ERROR: required main Lattice icon is missing." >&2
    exit 1
fi
if [[ ! -f "$SCRIPT_DIR/icons/lattice-nodes.png" ]]; then
    echo "ERROR: required Lattice Nodes icon is missing." >&2
    exit 1
fi

install -d -m 0755 /usr/share/pixmaps
install -m 0644 "$SCRIPT_DIR/icons/lattice-app.png" /usr/share/pixmaps/lattice.png
install -m 0644 "$SCRIPT_DIR/icons/lattice-nodes.png" /usr/share/pixmaps/lattice-nodes.png
chown root:root /usr/share/pixmaps/lattice.png /usr/share/pixmaps/lattice-nodes.png

if [[ -f "$SCRIPT_DIR/icons/lattice.png" ]]; then
    install -d -m 0755 /usr/share/icons/hicolor/256x256/apps
    install -m 0644 "$SCRIPT_DIR/icons/lattice.png" /usr/share/icons/hicolor/256x256/apps/lattice.png
    chown root:root /usr/share/icons/hicolor/256x256/apps/lattice.png
fi

if [[ ! -f "$SCRIPT_DIR/icons/lattice.svg" ]]; then
    echo "ERROR: required Lattice desktop icon is missing." >&2
    exit 1
fi
install -d -m 0755 /usr/share/icons/hicolor/scalable/apps
install -m 0644 "$SCRIPT_DIR/icons/lattice.svg" /usr/share/icons/hicolor/scalable/apps/lattice.svg
chown root:root /usr/share/icons/hicolor/scalable/apps/lattice.svg

SUDOERS_FILE="/etc/sudoers.d/lattice-action-exec"
{
    printf '%s\n' '# Lattice can perform one exact local recovery operation.'
    printf '%s ALL=(root) NOPASSWD: %s/bin/lattice-action-exec restart lattice-worker.service\n' \
        "$LATTICE_USER" "$INSTALL_ROOT"
    printf '%s ALL=(root) NOPASSWD: %s/bin/lattice-action-exec status lattice-worker.service\n' \
        "$LATTICE_USER" "$INSTALL_ROOT"
    printf '%s\n' '# Human backup changes cross privilege only through a strict object-ID helper.'
    printf '%%%s ALL=(root) NOPASSWD: %s/bin/lattice-backup-control *\n' \
        "$OPERATOR_GROUP" "$INSTALL_ROOT"
    printf '%s\n' '# Daily Care exposes only one local allowlisted run verb.'
    printf '%%%s ALL=(root) NOPASSWD: %s/bin/lattice-care-control run\n' \
        "$OPERATOR_GROUP" "$INSTALL_ROOT"
    printf '%s\n' '# Pairing and network helpers intentionally receive no daemon sudo access.'
    printf '%s\n' '# Pairing crosses root only through explicit local approval of one exact pending request.'
    printf '%s\n' '# Network changes remain root-only and separately authorized.'
} > "$SUDOERS_FILE"
chmod 0440 "$SUDOERS_FILE"
visudo -c -f "$SUDOERS_FILE" || { echo "ERROR: visudo rejected $SUDOERS_FILE" >&2; exit 1; }

ensure_existing_backup_identity() {
    [[ "$HAD_EXISTING_INSTALL" -eq 1 ]] || return 0
    [[ -f /etc/lattice/role ]] || return 0

    local role rc
    role="$(cat /etc/lattice/role 2>/dev/null || true)"
    case "$role" in
        master|worker) ;;
        *) return 0 ;;
    esac

    if "$ACTIVE_VENV/bin/python" -c '
from lattice.backup.identity import local_backup_identity
import sys
identity = local_backup_identity()
sys.exit(0 if identity is not None else 2)
'; then
        echo "  Backup transport identity: ready"
        return 0
    else
        rc=$?
    fi

    if [[ "$rc" -eq 2 ]]; then
        echo "  NOTICE: permanent Node identity is unavailable; Backup identity was not created."
        return 0
    fi
    echo "ERROR: could not provision the local Backup transport identity." >&2
    return "$rc"
}


restart_installed_runtime_services() {
    [[ "$HAD_EXISTING_INSTALL" -eq 1 ]] || return 0
    echo "==> Converging enabled Lattice runtime services onto the new release..."
    local unit
    for unit in "${RUNTIME_SERVICES[@]}"; do
        if systemctl is-enabled --quiet "$unit" 2>/dev/null || systemctl is-active --quiet "$unit" 2>/dev/null; then
            systemctl restart "$unit"
            echo "  restarted: $unit"
        fi
    done
}

converge_existing_care_units() {
    [[ "$HAD_EXISTING_INSTALL" -eq 1 ]] || return 0
    [[ -f /etc/lattice/role ]] || return 0
    local role
    role="$(cat /etc/lattice/role 2>/dev/null || true)"
    case "$role" in
        master|worker) ;;
        *) return 0 ;;
    esac
    systemctl enable lattice-care.timer
    echo "  enabled: lattice-care.timer (start after first local proof run)"
}

converge_existing_backup_units() {
    [[ "$HAD_EXISTING_INSTALL" -eq 1 ]] || return 0
    [[ -f /etc/lattice/role ]] || return 0

    local role unit
    local -a common_units=(
        lattice-backup.timer
        lattice-backup-maintenance.timer
        lattice-backup-run-request.path
        lattice-backup-query.path
        lattice-backup-restore.path
        lattice-backup-transport-reconcile.path
        lattice-backup-sshd.service
    )
    local -a master_units=(
        lattice-backup-alerts.timer
        lattice-backup-observation-refresh.timer
        lattice-backup-assignment-reconcile.timer
    )

    role="$(cat /etc/lattice/role 2>/dev/null || true)"
    case "$role" in
        master|worker) ;;
        *)
            echo "  NOTICE: existing install has no valid Lattice role; Backup units were not auto-enabled."
            return 0
            ;;
    esac

    echo "==> Converging Backup units for existing $role role..."
    for unit in "${common_units[@]}"; do
        systemctl enable --now "$unit"
        echo "  enabled: $unit"
    done
    if [[ "$role" == "master" ]]; then
        for unit in "${master_units[@]}"; do
            systemctl enable --now "$unit"
            echo "  enabled: $unit"
        done
    fi
}

prune_old_releases() {
    local active release index=0
    local -a releases=()
    active="$(readlink -f "$INSTALL_ROOT" 2>/dev/null || true)"
    while IFS= read -r release; do
        releases+=("$release")
    done < <(find "$RELEASES_ROOT" -mindepth 1 -maxdepth 1 -type d \
        -regextype posix-extended \
        -regex '.*/[0-9]{8}T[0-9]{6}Z-[0-9]+' -print | sort -r)
    for release in "${releases[@]}"; do
        index=$((index + 1))
        if (( index <= 3 )) || [[ "$release" == "$active" ]]; then
            continue
        fi
        rm -rf -- "$release"
        echo "  pruned old release: $(basename "$release")"
    done
}

# 7. systemd
echo ""
echo "==> [7/7] Installing systemd units..."
# Older releases installed a wildcard logrotate rule that could reload
# Lattice with unsupported SIGHUP and also matched the security audit log.
# Journald owns normal service logs; remove the obsolete rule on upgrades.
rm -f /etc/logrotate.d/lattice
SYSTEMD_DIR="/etc/systemd/system"
for unit in "$SCRIPT_DIR"/systemd/*.{service,socket,timer,path}; do
    [[ -f "$unit" ]] || continue
    install -m 0644 "$unit" "$SYSTEMD_DIR/"
done
systemctl daemon-reload

# Remove the obsolete pre-hardening socket unit from older installations.
# It must not remain enabled after an upgrade.
systemctl disable --now lattice-master.socket     >/dev/null 2>&1 || true
rm -f /etc/systemd/system/lattice-master.socket
systemctl daemon-reload

# A paired Worker's port-22 recovery entry is derived from a root-owned
# authority record. Once that authority exists, every upgrade repairs drift
# automatically without trusting daemon-writable pairing state as root trust.
if [[ -f /etc/lattice/role ]] && [[ "$(cat /etc/lattice/role 2>/dev/null || true)" == "worker" ]]; then
    if [[ -f /var/lib/lattice-root/recovery-authority.json ]]; then
        "$INSTALL_ROOT/bin/lattice-recovery-auth-exec" --repair
    elif [[ -f /var/lib/lattice/pairing.json ]] && grep -q '"state"[[:space:]]*:[[:space:]]*"paired"' /var/lib/lattice/pairing.json 2>/dev/null; then
        echo "  NOTICE: paired Worker uses a legacy recovery authorization generation."
        echo "          Run one locally approved recovery migration after verifying the Master key fingerprint."
    fi
fi

ensure_existing_backup_identity
restart_installed_runtime_services
converge_existing_backup_units
converge_existing_care_units
prune_old_releases

# Install launch-ready shortcuts for the human user who invoked sudo.
install_lattice_desktop_shortcuts() {
    local desktop_user="${SUDO_USER:-}"
    local user_home user_group user_uid desktop_dir configured
    local app_target nodes_target user_bus

    if [[ -z "$desktop_user" || "$desktop_user" == "root" ]]; then
        echo "  NOTICE: no non-root SUDO_USER detected; desktop shortcuts were not created."
        return 0
    fi

    user_home="$(getent passwd "$desktop_user" | cut -d: -f6)"
    user_group="$(id -gn "$desktop_user")"
    user_uid="$(id -u "$desktop_user")"

    if [[ -z "$user_home" || ! -d "$user_home" ]]; then
        echo "ERROR: cannot determine Desktop owner home for $desktop_user." >&2
        return 1
    fi

    desktop_dir="$user_home/Desktop"

    if [[ -r "$user_home/.config/user-dirs.dirs" ]]; then
        configured="$(
            sed -n 's/^XDG_DESKTOP_DIR="\(.*\)"$/\1/p' \
                "$user_home/.config/user-dirs.dirs" | head -n 1
        )"
        if [[ -n "$configured" ]]; then
            configured="${configured//\$HOME/$user_home}"
            if [[ "$configured" == /* ]]; then
                desktop_dir="$configured"
            fi
        fi
    fi

    install -d -m 0755 -o "$desktop_user" -g "$user_group" "$desktop_dir"

    app_target="$desktop_dir/lattice.desktop"
    nodes_target="$desktop_dir/lattice-nodes.desktop"

    # Remove legacy capitalized launcher names.  Ubuntu may have rewritten a
    # previous Nodes shortcut into a second main-Lattice shortcut, so accept
    # either Lattice's marker or one of its two known helper paths as proof
    # that the file is safe for Lattice to remove.
    for legacy in \
        "$desktop_dir/Lattice.desktop" \
        "$desktop_dir/Lattice Nodes.desktop"
    do
        if [[ -f "$legacy" ]] && {
            grep -q '^X-Lattice-Managed=true$' "$legacy" 2>/dev/null ||
            grep -q '^Exec=/opt/lattice/bin/lattice-tui-open$' "$legacy" 2>/dev/null ||
            grep -q '^Exec=/opt/lattice/bin/lattice-desktop-open$' "$legacy" 2>/dev/null
        }; then
            rm -f -- "$legacy"
        fi
    done

    for existing in "$app_target" "$nodes_target"; do
        if [[ -e "$existing" ]] &&
           ! grep -q '^X-Lattice-Managed=true$' "$existing" 2>/dev/null; then
            echo "ERROR: refusing to overwrite unmanaged desktop shortcut: $existing" >&2
            return 1
        fi
    done

    install -m 0755 -o "$desktop_user" -g "$user_group" \
        "$SCRIPT_DIR/applications/lattice.desktop" "$app_target"

    install -m 0755 -o "$desktop_user" -g "$user_group" \
        "$SCRIPT_DIR/applications/lattice-nodes.desktop" "$nodes_target"

    # Verify the Desktop copies are exactly the intended launchers.
    if ! cmp -s "$SCRIPT_DIR/applications/lattice.desktop" "$app_target"; then
        echo "ERROR: main Lattice Desktop shortcut was not installed correctly." >&2
        return 1
    fi

    if ! cmp -s "$SCRIPT_DIR/applications/lattice-nodes.desktop" "$nodes_target"; then
        echo "ERROR: Lattice Nodes Desktop shortcut was not installed correctly." >&2
        return 1
    fi

    # GNOME/Nemo/Cinnamon may require trusted metadata in addition to +x.
    # Set it through the actual user's session bus when available.
    if command -v gio >/dev/null 2>&1; then
        user_bus="/run/user/$user_uid/bus"
        if [[ -S "$user_bus" ]]; then
            runuser -u "$desktop_user" -- env \
                HOME="$user_home" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus" \
                gio set "$app_target" metadata::trusted true \
                >/dev/null 2>&1 || true

            runuser -u "$desktop_user" -- env \
                HOME="$user_home" \
                DBUS_SESSION_BUS_ADDRESS="unix:path=$user_bus" \
                gio set "$nodes_target" metadata::trusted true \
                >/dev/null 2>&1 || true
        else
            runuser -u "$desktop_user" -- env HOME="$user_home" \
                gio set "$app_target" metadata::trusted true \
                >/dev/null 2>&1 || true
            runuser -u "$desktop_user" -- env HOME="$user_home" \
                gio set "$nodes_target" metadata::trusted true \
                >/dev/null 2>&1 || true
        fi
    fi

    echo "  desktop shortcut: $app_target"
    echo "  desktop shortcut: $nodes_target"
}

install_lattice_desktop_shortcuts

echo ""
echo "=================================================="
echo "  Lattice files are installed."
if [[ "$HAD_EXISTING_INSTALL" -eq 1 ]]; then
    echo "  Existing enabled Lattice runtime services were restarted onto this release."
else
    echo "  No master or worker service has been started."
    echo "  Continue with: sudo lattice init"
fi
if [[ "$OPERATOR_MEMBERSHIP_ADDED" -eq 1 ]]; then
    echo "  NOTICE: log out and back in before using Lattice without sudo so the lattice-operator group becomes active."
fi
trap - ERR INT TERM
cleanup_install_snapshot
echo "=================================================="
