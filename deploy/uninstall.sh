#!/bin/bash
# Lattice uninstaller. Stops services, removes units and files.
# Pass --purge to also remove Lattice state, logs, and settings.
set -euo pipefail

PURGE=false
NETWORK_MODE="prompt"

for arg in "$@"; do
    case "$arg" in
        --purge)
            PURGE=true
            ;;
        --restore-network)
            if [[ "$NETWORK_MODE" == "keep" ]]; then
                echo "ERROR: --restore-network conflicts with --keep-network" >&2
                exit 2
            fi
            NETWORK_MODE="restore"
            ;;
        --keep-network)
            if [[ "$NETWORK_MODE" == "restore" ]]; then
                echo "ERROR: --keep-network conflicts with --restore-network" >&2
                exit 2
            fi
            NETWORK_MODE="keep"
            ;;
        *)
            echo "ERROR: Unknown uninstall option: $arg" >&2
            exit 2
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: uninstall.sh must be run as root (use sudo)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=host-state.sh
source "$SCRIPT_DIR/host-state.sh"

LATTICE_USER="lattice"
LATTICE_GROUP="lattice"
OPERATOR_GROUP="lattice-operator"
MANAGED_ACCOUNT_ROOT="/var/lib/lattice-root"

trusted_account_marker() {
    local path="$1"
    local owner mode numeric_mode

    [[ -f "$path" && ! -L "$path" ]] || return 1

    owner="$(stat -c '%u' "$path" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$path" 2>/dev/null || true)"

    [[ "$owner" == "0" && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1

    numeric_mode=$((8#$mode))
    (( (numeric_mode & 0022) == 0 ))
}

REMOVE_LATTICE_USER=false
REMOVE_LATTICE_GROUP=false
REMOVE_OPERATOR_GROUP=false
MANAGED_OPERATOR_MEMBERS=()

trusted_account_marker "$MANAGED_ACCOUNT_ROOT/managed-user-lattice" \
    && REMOVE_LATTICE_USER=true

trusted_account_marker "$MANAGED_ACCOUNT_ROOT/managed-group-lattice" \
    && REMOVE_LATTICE_GROUP=true

trusted_account_marker "$MANAGED_ACCOUNT_ROOT/managed-group-lattice-operator" \
    && REMOVE_OPERATOR_GROUP=true

if trusted_account_marker "$MANAGED_ACCOUNT_ROOT/managed-operator-members"; then
    while IFS= read -r member; do
        if [[ "$member" =~ ^[A-Za-z0-9._-]+$ ]]; then
            MANAGED_OPERATOR_MEMBERS+=("$member")
        fi
    done < "$MANAGED_ACCOUNT_ROOT/managed-operator-members"
fi

remove_managed_accounts() {
    local member

    for member in "${MANAGED_OPERATOR_MEMBERS[@]}"; do
        if getent group "$OPERATOR_GROUP" >/dev/null \
           && id "$member" >/dev/null 2>&1; then
            gpasswd -d "$member" "$OPERATOR_GROUP" >/dev/null 2>&1 || {
                echo "WARNING: Could not remove $member from $OPERATOR_GROUP." >&2
            }
        fi
    done

    if [[ "$REMOVE_LATTICE_USER" == "true" ]] \
       && id "$LATTICE_USER" >/dev/null 2>&1; then
        if pgrep -u "$LATTICE_USER" >/dev/null 2>&1; then
            echo "WARNING: $LATTICE_USER still has running processes; account was left in place." >&2
        else
            userdel "$LATTICE_USER" || {
                echo "WARNING: Could not remove managed user $LATTICE_USER." >&2
            }
        fi
    fi

    if [[ "$REMOVE_LATTICE_GROUP" == "true" ]] \
       && getent group "$LATTICE_GROUP" >/dev/null; then
        groupdel "$LATTICE_GROUP" || {
            echo "WARNING: Could not remove managed group $LATTICE_GROUP." >&2
        }
    fi

    if [[ "$REMOVE_OPERATOR_GROUP" == "true" ]] \
       && getent group "$OPERATOR_GROUP" >/dev/null; then
        groupdel "$OPERATOR_GROUP" || {
            echo "WARNING: Could not remove managed group $OPERATOR_GROUP." >&2
        }
    fi
}

cleanup_empty_lattice_mount_roots() {
    local path child name

    # Peer mount points are UUIDv4 directories directly below /mnt/lattice.
    # Remove only empty, unmounted directories with that exact shape.
    # Unknown files/directories are deliberately preserved and will make the
    # final verification warn instead of being deleted.
    if [[ -d /mnt/lattice ]]; then
        if findmnt -rn -o TARGET 2>/dev/null \
            | grep -Eq '^/mnt/lattice(/|$)'; then
            echo "WARNING: /mnt/lattice still contains mounted filesystems; leaving it untouched." >&2
        else
            for child in /mnt/lattice/*; do
                [[ -d "$child" && ! -L "$child" ]] || continue
                name="${child##*/}"

                if [[ "$name" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]; then
                    rmdir -- "$child" 2>/dev/null || true
                fi
            done
        fi
    fi

    if [[ -d /srv/lattice-backup-chroot ]]; then
        for child in /srv/lattice-backup-chroot/lattice-bkp-*; do
            [[ -d "$child" && ! -L "$child" ]] || continue
            name="${child##*/}"
            [[ "$name" =~ ^lattice-bkp-[0-9a-f]{20}$ ]] || continue
            if mountpoint -q "$child/repo" 2>/dev/null; then
                echo "WARNING: $child/repo is still mounted; leaving backup chroot untouched." >&2
                continue
            fi
            rmdir -- "$child/repo" 2>/dev/null || true
            rmdir -- "$child" 2>/dev/null || true
        done
        rmdir -- /srv/lattice-backup-chroot 2>/dev/null || true
    fi

    for path in /srv/lattice-file-root/Home /srv/lattice-file-root /mnt/lattice; do
        if mountpoint -q "$path" 2>/dev/null; then
            echo "WARNING: $path is still mounted; leaving it untouched." >&2
        elif [[ -d "$path" ]]; then
            if ! rmdir -- "$path" 2>/dev/null; then
                echo "WARNING: $path is not empty; leaving it untouched." >&2
            fi
        fi
    done
}

verify_uninstall() {
    local leftovers=0
    local path

    echo "==> Verifying uninstall..."

    if systemctl list-unit-files --no-legend 2>/dev/null \
        | grep -q '^lattice-'; then
        echo "WARNING: Lattice systemd unit files remain." >&2
        leftovers=1
    fi

    if findmnt -rn -o TARGET 2>/dev/null \
        | grep -Eq '^(/srv/lattice-file-root|/srv/lattice-backup-chroot|/mnt/lattice)(/|$)'; then
        echo "WARNING: Lattice mounts remain." >&2
        leftovers=1
    fi

    if ps -eo pid=,args= | awk '
        /\/deploy\/uninstall\.sh/ { next }
        /\/opt\/lattice/ { found=1 }
        /lattice\.(daemon|worker|file_access|shell_access|backup|credential_revoke|ip_change)/ { found=1 }
        END { exit found ? 0 : 1 }
    '; then
        echo "WARNING: Lattice processes remain." >&2
        leftovers=1
    fi

    # These must disappear for both normal uninstall and --purge.
    for path in \
        /opt/lattice \
        /opt/lattice-releases \
        /run/lattice \
        /run/lattice-operator \
        /run/lattice-wizard.lock \
        /srv/lattice-file-root \
        /srv/lattice-backup-chroot \
        /mnt/lattice
    do
        if [[ -e "$path" || -L "$path" ]]; then
            echo "WARNING: leftover path: $path" >&2
            leftovers=1
        fi
    done

    # Configuration, durable state, and logs are intentionally preserved
    # by a normal uninstall and must disappear only for --purge.
    if [[ "$PURGE" == "true" ]]; then
        for path in \
            /etc/lattice \
            /var/lib/lattice \
            /var/lib/lattice-root \
            /var/log/lattice
        do
            if [[ -e "$path" || -L "$path" ]]; then
                echo "WARNING: leftover purge path: $path" >&2
                leftovers=1
            fi
        done
    fi

    if compgen -G '/run/systemd/propagate/lattice-*' >/dev/null; then
        echo "WARNING: Lattice systemd propagation state remains." >&2
        leftovers=1
    fi

    if [[ -d /srv/lattice-file-root ]]; then
        echo "WARNING: leftover path: /srv/lattice-file-root" >&2
        leftovers=1
    fi

    if [[ "$PURGE" == "true" && "$REMOVE_LATTICE_USER" == "true" ]] \
       && id "$LATTICE_USER" >/dev/null 2>&1; then
        echo "WARNING: managed Lattice user remains." >&2
        leftovers=1
    fi

    if [[ "$PURGE" == "true" && "$REMOVE_LATTICE_GROUP" == "true" ]] \
       && getent group "$LATTICE_GROUP" >/dev/null; then
        echo "WARNING: managed Lattice group remains." >&2
        leftovers=1
    fi

    if [[ "$PURGE" == "true" && "$REMOVE_OPERATOR_GROUP" == "true" ]] \
       && getent group "$OPERATOR_GROUP" >/dev/null; then
        echo "WARNING: managed Lattice operator group remains." >&2
        leftovers=1
    fi

    if [[ "$leftovers" -eq 0 ]]; then
        echo "  uninstall verification clean"
        return 0
    fi

    return 1
}

validate_cleanup_python() {
    local candidate="$1"
    local release_root

    [[ -x "$candidate" ]] || return 1

    if [[ "$candidate" == /opt/lattice/venv/bin/python ]]; then
        release_root="$(readlink -f /opt/lattice 2>/dev/null || true)"
    else
        release_root="${candidate%/venv/bin/python}"
    fi

    [[ -n "$release_root" && -d "$release_root" ]] || return 1

    # Installed releases are root-owned and must not be writable by group/other.
    local owner mode
    owner="$(stat -c '%u' "$release_root" 2>/dev/null || true)"
    mode="$(stat -c '%a' "$release_root" 2>/dev/null || true)"

    [[ "$owner" == "0" ]] || return 1

    if [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
        local numeric_mode
        numeric_mode=$((8#$mode))
        (( (numeric_mode & 0022) == 0 )) || return 1
    else
        return 1
    fi

    # Isolated mode removes the caller's current directory and Python
    # environment variables from import resolution. Also prove that the
    # imported lattice package belongs to this exact trusted release.
    "$candidate" -I -c '
import pathlib
import sys
import lattice

release = pathlib.Path(sys.argv[1]).resolve()
module = pathlib.Path(lattice.__file__).resolve()

raise SystemExit(
    0 if module.is_relative_to(release) else 1
)
' "$release_root" >/dev/null 2>&1 || return 1

    return 0
}


find_cleanup_python() {
    local candidate

    candidate="/opt/lattice/venv/bin/python"

    if validate_cleanup_python "$candidate"; then
        printf '%s\n' "$candidate"
        return 0
    fi

    if [[ -d /opt/lattice-releases ]]; then
        while IFS= read -r candidate; do
            if validate_cleanup_python "$candidate"; then
                printf '%s\n' "$candidate"
                return 0
            fi
        done < <(
            find /opt/lattice-releases                 -mindepth 4                 -maxdepth 4                 -path '*/venv/bin/python'                 -print 2>/dev/null                 | sort -r
        )
    fi

    return 1
}


CLEANUP_PYTHON="$(find_cleanup_python || true)"

# Pairing/firewall state may represent external privileges or rules that must
# be removed before program files disappear. Never silently skip this cleanup.
SECURITY_CLEANUP_REQUIRED=false

if [[ -e /var/lib/lattice/pairing.json       || -L /var/lib/lattice/pairing.json       || -e /etc/lattice/firewall-rules.json       || -L /etc/lattice/firewall-rules.json ]]; then
    SECURITY_CLEANUP_REQUIRED=true
fi

if [[ "$SECURITY_CLEANUP_REQUIRED" == "true"       && -z "$CLEANUP_PYTHON" ]]; then
    echo "ERROR: Lattice security state exists, but no trustworthy installed Lattice interpreter is available." >&2
    echo "Uninstall stopped before removing program files so pairing/firewall cleanup is not silently skipped." >&2
    false
fi

if [[ "$PURGE" == "true" && -z "$CLEANUP_PYTHON" ]]; then
    if [[ -e /srv/lattice-file-root/Home || -d /mnt/lattice ]]; then
        echo "ERROR: Lattice file/mount state exists, but no trustworthy installed Lattice interpreter is available." >&2
        echo "Purge stopped so a Home bind or peer mount can never be traversed by recursive deletion." >&2
        false
    fi
fi

if [[ -n "$CLEANUP_PYTHON" ]]; then
    echo "==> Removing Lattice desktop/file-manager integration..."

    "$CLEANUP_PYTHON" -I -m lattice.file_access.desktop --remove || {
        echo "WARNING: Could not completely remove user-facing Lattice shortcuts." >&2
    }

    echo "==> Removing this machine's recorded Lattice pairing credentials..."

    "$CLEANUP_PYTHON" -I -m lattice.credential_revoke --uninstall || {
        echo "ERROR: Lattice pairing credentials could not be removed safely; uninstall stopped." >&2
        false
    }

    "$CLEANUP_PYTHON" -I -m lattice.core.ssh_firewall --remove-lattice-rules || {
        echo "ERROR: Recorded Lattice firewall rules could not be removed safely; uninstall stopped." >&2
        false
    }
fi
rm -f /etc/avahi/services/lattice.service
systemctl reload avahi-daemon 2>/dev/null || true

# Prevent a network-healing component from racing the uninstall rollback.
# These stops intentionally happen before the saved NetworkManager profile
# is restored. The normal full service-stop phase later is still retained.
systemctl stop lattice-network-reconcile.timer 2>/dev/null || true
systemctl stop lattice-network-reconcile.service 2>/dev/null || true
systemctl stop lattice-network-assignment.path 2>/dev/null || true
systemctl stop lattice-network-assignment.service 2>/dev/null || true
systemctl stop lattice-boot-recovery.service 2>/dev/null || true

if [[ -f /var/lib/lattice-root/ipchange.state \
      || -f /var/lib/lattice-root/ipchange.original.json ]]; then
    echo "Lattice previously changed this computer's network settings."
    echo "Choose: [K]eep the current static address or [R]estore the saved DHCP/network settings."

    NETWORK_CHOICE="K"

    if [[ "$NETWORK_MODE" == "restore" ]]; then
        NETWORK_CHOICE="R"
        echo "Explicit network restore requested."
    elif [[ "$NETWORK_MODE" == "keep" ]]; then
        NETWORK_CHOICE="K"
        echo "Explicitly keeping the current working address."
    elif [[ -t 0 ]]; then
        read -r -p "Keep or restore? [K/r]: " NETWORK_CHOICE
    else
        echo "No interactive terminal is available; keeping the current working address."
    fi

    if [[ "$NETWORK_CHOICE" == "r"           || "$NETWORK_CHOICE" == "R" ]]; then

        if [[ -z "$CLEANUP_PYTHON" ]]; then
            echo "ERROR: Network restore was requested, but no trustworthy installed Lattice interpreter is available." >&2
            echo "The saved network state and program files were left in place." >&2
            false
        fi

        "$CLEANUP_PYTHON" -I -m lattice.ip_change.uninstall_restore || {
            echo "ERROR: Network restore failed. Lattice files were not removed." >&2
            echo "Emergency retry using: sudo $CLEANUP_PYTHON -I -m lattice.ip_change.uninstall_restore" >&2
            false
        }

        echo "Saved pre-Lattice network settings restored."
    else
        echo "Keeping the current static network settings."
    fi
fi

echo "==> Stopping services..."
systemctl stop lattice-master.service 2>/dev/null || true
systemctl stop lattice-master.socket 2>/dev/null || true
systemctl stop lattice-worker.service 2>/dev/null || true
systemctl stop lattice-mount-manager.service 2>/dev/null || true
systemctl stop lattice-file-sshd.service 2>/dev/null || true
systemctl stop lattice-shell-connection-manager.service 2>/dev/null || true
systemctl stop lattice-shell-sshd.service 2>/dev/null || true
systemctl stop lattice-file-transport-reconcile.path 2>/dev/null || true
systemctl stop lattice-file-transport-reconcile.service 2>/dev/null || true
systemctl stop lattice-backup-transport-reconcile.path 2>/dev/null || true
systemctl stop lattice-backup-transport-reconcile.service 2>/dev/null || true
systemctl stop lattice-backup-sshd.service 2>/dev/null || true
systemctl stop lattice-init.service 2>/dev/null || true
systemctl stop lattice-boot-recovery.service 2>/dev/null || true
systemctl stop lattice-health-watchdog.timer 2>/dev/null || true
systemctl stop lattice-backup.timer 2>/dev/null || true
systemctl stop lattice-backup.service 2>/dev/null || true
systemctl stop lattice-backup-run-request.path 2>/dev/null || true
systemctl stop lattice-backup-run-request.service 2>/dev/null || true
systemctl stop lattice-backup-query.path 2>/dev/null || true
systemctl stop lattice-backup-query.service 2>/dev/null || true
systemctl stop lattice-backup-restore.path 2>/dev/null || true
systemctl stop lattice-backup-restore.service 2>/dev/null || true
systemctl stop lattice-backup-maintenance.timer 2>/dev/null || true
systemctl stop lattice-backup-maintenance.service 2>/dev/null || true
systemctl stop lattice-backup-alerts.timer 2>/dev/null || true
systemctl stop lattice-backup-alerts.service 2>/dev/null || true
systemctl stop lattice-care.timer 2>/dev/null || true
systemctl stop lattice-care.service 2>/dev/null || true
systemctl stop lattice-backup-observation-refresh.timer 2>/dev/null || true
systemctl stop lattice-backup-observation-refresh.service 2>/dev/null || true
systemctl stop lattice-backup-assignment-reconcile.timer 2>/dev/null || true
systemctl stop lattice-backup-assignment-reconcile.service 2>/dev/null || true
systemctl stop lattice-health-check.service 2>/dev/null || true
systemctl stop lattice-network-assignment.path 2>/dev/null || true
systemctl stop lattice-network-assignment.service 2>/dev/null || true
systemctl stop lattice-network-reconcile.timer 2>/dev/null || true
systemctl stop lattice-network-reconcile.service 2>/dev/null || true
systemctl stop lattice-credential-revoke.path 2>/dev/null || true
systemctl stop lattice-credential-revoke.service 2>/dev/null || true

# Detach every Lattice-owned filesystem view before removing any state.
# This is mandatory for --purge: /srv/lattice-file-root/Home is a bind
# view of the real user Home and must never be traversed by recursive cleanup.
if [[ -n "$CLEANUP_PYTHON" ]]; then
    echo "==> Detaching Lattice file mounts safely..."
    "$CLEANUP_PYTHON" -I -m lattice.file_access.uninstall_cleanup || {
        echo "ERROR: Lattice mounts could not be detached safely; uninstall stopped before data removal." >&2
        false
    }
fi

# Only remove empty, unmounted mount-point directories. Never recursively
# delete here because Home may previously have been a bind mount.
cleanup_empty_lattice_mount_roots

systemctl disable lattice-master.service 2>/dev/null || true
systemctl disable lattice-master.socket 2>/dev/null || true
systemctl disable lattice-worker.service 2>/dev/null || true
systemctl disable lattice-mount-manager.service 2>/dev/null || true
systemctl disable lattice-file-sshd.service 2>/dev/null || true
systemctl disable lattice-shell-connection-manager.service 2>/dev/null || true
systemctl disable lattice-shell-sshd.service 2>/dev/null || true
systemctl disable lattice-file-transport-reconcile.path 2>/dev/null || true
systemctl disable lattice-backup-transport-reconcile.path 2>/dev/null || true
systemctl disable lattice-backup-sshd.service 2>/dev/null || true
systemctl disable lattice-init.service 2>/dev/null || true
systemctl disable lattice-boot-recovery.service 2>/dev/null || true
systemctl disable lattice-health-watchdog.timer 2>/dev/null || true
systemctl disable lattice-backup.timer 2>/dev/null || true
systemctl disable lattice-backup-run-request.path 2>/dev/null || true
systemctl disable lattice-backup-query.path 2>/dev/null || true
systemctl disable lattice-backup-restore.path 2>/dev/null || true
systemctl disable lattice-backup-maintenance.timer 2>/dev/null || true
systemctl disable lattice-backup-alerts.timer 2>/dev/null || true
systemctl disable lattice-care.timer 2>/dev/null || true
systemctl disable lattice-backup-observation-refresh.timer 2>/dev/null || true
systemctl disable lattice-backup-assignment-reconcile.timer 2>/dev/null || true
systemctl disable lattice-health-check.service 2>/dev/null || true
systemctl disable lattice-network-assignment.path 2>/dev/null || true
systemctl disable lattice-network-reconcile.service 2>/dev/null || true
systemctl disable lattice-network-reconcile.timer 2>/dev/null || true
systemctl disable lattice-credential-revoke.path 2>/dev/null || true

echo "==> Removing unit files..."
for unit in lattice-init.service lattice-master.service lattice-worker.service lattice-mount-manager.service lattice-file-sshd.service lattice-shell-sshd.service lattice-shell-connection-manager.service lattice-file-transport-reconcile.path lattice-file-transport-reconcile.service lattice-backup-transport-reconcile.path lattice-backup-transport-reconcile.service lattice-backup-sshd.service lattice-master.socket lattice-boot-recovery.service lattice-health-check.service lattice-health-watchdog.timer lattice-backup.timer lattice-backup.service lattice-backup-run-request.path lattice-backup-run-request.service lattice-backup-query.path lattice-backup-query.service lattice-backup-restore.path lattice-backup-restore.service lattice-backup-maintenance.timer lattice-backup-maintenance.service lattice-backup-alerts.timer lattice-backup-alerts.service lattice-backup-observation-refresh.timer lattice-backup-observation-refresh.service lattice-care.timer lattice-care.service lattice-backup-assignment-reconcile.timer lattice-backup-assignment-reconcile.service lattice-network-assignment.path lattice-network-assignment.service lattice-network-reconcile.service lattice-network-reconcile.timer lattice-credential-revoke.path lattice-credential-revoke.service; do
    rm -f "/etc/systemd/system/$unit"
done
systemctl daemon-reload

# Remove runtime-only state that can survive service/unit removal until reboot.
rm -f /run/lattice-wizard.lock
rm -rf /run/lattice /run/lattice-operator

for path in /run/systemd/propagate/lattice-*; do
    [[ -e "$path" ]] || continue

    if [[ -d "$path" && ! -L "$path" ]]; then
        rmdir -- "$path" 2>/dev/null || true
    fi
done

rm -f /etc/sudoers.d/lattice-action-exec
rm -f /opt/lattice/bin/lattice-care-control 2>/dev/null || true
rm -f /opt/lattice/bin/lattice-verification-control 2>/dev/null || true
rm -f /etc/sudoers.d/lattice-shell-admin
rm -f /etc/ssh/ssh_config.d/90-lattice-shell.conf
rm -f /etc/sudoers.d/lattice-remote-heal-*
rm -f /etc/logrotate.d/lattice /etc/tmpfiles.d/lattice.conf /etc/sysusers.d/lattice.conf
rm -f /usr/share/applications/lattice.desktop
rm -f /usr/share/applications/lattice-nodes.desktop
rm -f /usr/share/pixmaps/lattice.png
rm -f /usr/share/pixmaps/lattice-nodes.png
rm -f /usr/share/icons/hicolor/256x256/apps/lattice.png
rm -f /usr/share/icons/hicolor/scalable/apps/lattice.svg

remove_managed_desktop_shortcuts() {
    local desktop_user="${SUDO_USER:-}"
    local user_home desktop_dir configured shortcut

    if [[ -z "$desktop_user" || "$desktop_user" == "root" ]]; then
        return 0
    fi

    user_home="$(getent passwd "$desktop_user" | cut -d: -f6)"
    [[ -n "$user_home" && -d "$user_home" ]] || return 0

    desktop_dir="$user_home/Desktop"

    if [[ -r "$user_home/.config/user-dirs.dirs" ]]; then
        configured="$(
            sed -n 's/^XDG_DESKTOP_DIR="\(.*\)"$/\1/p'                 "$user_home/.config/user-dirs.dirs" | head -n 1
        )"
        if [[ -n "$configured" ]]; then
            configured="${configured//\$HOME/$user_home}"
            [[ "$configured" == /* ]] && desktop_dir="$configured"
        fi
    fi

    for shortcut in \
        "$desktop_dir/lattice.desktop" \
        "$desktop_dir/lattice-nodes.desktop" \
        "$desktop_dir/Lattice.desktop" \
        "$desktop_dir/Lattice Nodes.desktop"
    do
        [[ -f "$shortcut" ]] || continue

        if grep -q '^X-Lattice-Managed=true$' "$shortcut" 2>/dev/null; then
            rm -f -- "$shortcut"
            echo "  removed desktop shortcut: $shortcut"
        else
            echo "WARNING: desktop shortcut is not Lattice-managed; leaving it untouched: $shortcut" >&2
        fi
    done
}

remove_managed_desktop_shortcuts
if [[ -L /usr/local/bin/lattice \
      && "$(readlink /usr/local/bin/lattice 2>/dev/null || true)" == "/opt/lattice/venv/bin/lattice" ]]; then
    rm -f /usr/local/bin/lattice
elif [[ -e /usr/local/bin/lattice || -L /usr/local/bin/lattice ]]; then
    echo "WARNING: /usr/local/bin/lattice is not the Lattice-managed launcher; leaving it untouched." >&2
fi
rm -rf /opt/lattice
rm -rf /opt/lattice-releases

if [[ "$PURGE" == "true" ]]; then
    echo "==> Removing Lattice-managed accounts..."
    remove_managed_accounts

    echo "==> Restoring pre-Lattice package and service state..."
    HOST_STATE_RESTORE_OK=true
    if ! lattice_host_state_restore; then
        HOST_STATE_RESTORE_OK=false
        echo "WARNING: host-state restoration was incomplete; preserving the root-owned restoration record and failing verification." >&2
    fi

    echo "==> Purging data directories..."
    rm -rf /var/lib/lattice /var/log/lattice /etc/lattice /run/lattice /run/lattice-operator
    if [[ "$HOST_STATE_RESTORE_OK" == "true" ]]; then
        rm -rf /var/lib/lattice-root
    else
        echo "WARNING: preserved /var/lib/lattice-root so host restoration can be diagnosed or retried." >&2
    fi
    rm -f /etc/sysusers.d/lattice.conf /etc/tmpfiles.d/lattice.conf /etc/logrotate.d/lattice

    # Retry empty mount-root cleanup after all Lattice runtime state is gone.
    cleanup_empty_lattice_mount_roots
else
    echo "(Preserved configuration, logs, state, and managed accounts — use --purge to remove them)"
fi

echo ""
if verify_uninstall; then
    echo "Lattice program files and service integration were removed."
    echo "Your network choice was respected. Only recorded Lattice SSH and firewall entries were removed; personal settings were left unchanged."
else
    echo "ERROR: Lattice uninstall completed with residue. Review the warnings above." >&2
    exit 1
fi
