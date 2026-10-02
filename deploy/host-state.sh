#!/bin/bash
# Root-private record of host state that existed before the first Lattice install.
# Sourced by install.sh and uninstall.sh; never execute directly.

LATTICE_HOST_STATE_ROOT="/var/lib/lattice-root"
LATTICE_HOST_STATE_MARKER="$LATTICE_HOST_STATE_ROOT/host-state-v1"
HOST_STATE_CREATED_THIS_INSTALL=0

_lattice_install_preflight() {
    [[ "$(basename -- "$0")" == "install.sh" ]] || return 0

    # The managed trusted-shell channel is intentionally restarted during
    # convergence. Refuse to let an installer destroy the session carrying
    # itself; use a local console or the independent port-22 admin/recovery SSH.
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local _client_ip _client_port _server_ip server_port
        read -r _client_ip _client_port _server_ip server_port <<< "$SSH_CONNECTION"
        if [[ "$server_port" == "22023" ]]; then
            echo "ERROR: do not install or upgrade Lattice through managed trusted-shell port 22023." >&2
            echo "       Use the local console or normal admin/recovery SSH on port 22." >&2
            exit 1
        fi
    fi

    # A source tree without Git metadata cannot distinguish committed release
    # files from arbitrary extra files. Require a complete checkout so staging
    # remains deterministic and tracked-only.
    local source_root
    source_root="${LATTICE_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
    if [[ ! -d "$source_root/.git" ]]; then
        echo "ERROR: Lattice installation requires a complete Git checkout with .git metadata." >&2
        echo "       If you copied the repository, copy the complete checkout including .git." >&2
        exit 1
    fi
}

_lattice_install_preflight

lattice_host_state_snapshot() {
    if [[ -f "$LATTICE_HOST_STATE_MARKER" ]]; then
        HOST_STATE_CREATED_THIS_INSTALL=0
        return 0
    fi
    install -d -m 0700 -o root -g root "$LATTICE_HOST_STATE_ROOT"
    local tmp="$LATTICE_HOST_STATE_ROOT/.snapshot.$$"
    install -d -m 0700 -o root -g root "$tmp"
    dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u > "$tmp/packages-before.txt"
    apt-mark showmanual 2>/dev/null | sort -u > "$tmp/manual-before.txt" || true
    : > "$tmp/services-before.tsv"
    local unit load active enabled
    for unit in ssh.service sshd.service avahi-daemon.service ufw.service; do
        load="$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)"
        active="$(systemctl is-active "$unit" 2>/dev/null || true)"
        enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
        printf '%s\t%s\t%s\t%s\n' "$unit" "${load:-not-found}" "${active:-inactive}" "${enabled:-disabled}" >> "$tmp/services-before.tsv"
    done
    install -m 0600 -o root -g root "$tmp/packages-before.txt" "$LATTICE_HOST_STATE_ROOT/packages-before.txt"
    install -m 0600 -o root -g root "$tmp/manual-before.txt" "$LATTICE_HOST_STATE_ROOT/manual-before.txt"
    install -m 0600 -o root -g root "$tmp/services-before.tsv" "$LATTICE_HOST_STATE_ROOT/services-before.tsv"
    printf '1\n' > "$LATTICE_HOST_STATE_MARKER"
    chmod 0600 "$LATTICE_HOST_STATE_MARKER"
    rm -rf -- "$tmp"
    HOST_STATE_CREATED_THIS_INSTALL=1
}

lattice_host_state_plan_packages() {
    [[ "$HOST_STATE_CREATED_THIS_INSTALL" -eq 1 ]] || return 0
    [[ "$#" -gt 0 ]] || return 0
    printf '%s\n' "$@" | sort -u > "$LATTICE_HOST_STATE_ROOT/requested-packages.txt"
    chmod 0600 "$LATTICE_HOST_STATE_ROOT/requested-packages.txt"
    local simulation
    simulation="$(DEBIAN_FRONTEND=noninteractive apt-get -s install --no-upgrade -y -- "$@" 2>/dev/null || true)"
    printf '%s\n' "$simulation" | awk '/^Inst /{print $2}' | sort -u > "$LATTICE_HOST_STATE_ROOT/packages-planned-by-lattice.txt"
    chmod 0600 "$LATTICE_HOST_STATE_ROOT/packages-planned-by-lattice.txt"
}

lattice_host_state_finalize_packages() {
    [[ "$HOST_STATE_CREATED_THIS_INSTALL" -eq 1 ]] || return 0
    local now="$LATTICE_HOST_STATE_ROOT/packages-after.txt"
    local manual_now="$LATTICE_HOST_STATE_ROOT/manual-after.txt"
    dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u > "$now"
    apt-mark showmanual 2>/dev/null | sort -u > "$manual_now" || true
    comm -13 "$LATTICE_HOST_STATE_ROOT/packages-before.txt" "$now" > "$LATTICE_HOST_STATE_ROOT/packages-added-by-lattice.txt"
    comm -13 "$LATTICE_HOST_STATE_ROOT/manual-before.txt" "$manual_now" > "$LATTICE_HOST_STATE_ROOT/.manual-added.$$"
    if [[ -f "$LATTICE_HOST_STATE_ROOT/requested-packages.txt" ]]; then
        comm -12 "$LATTICE_HOST_STATE_ROOT/.manual-added.$$" "$LATTICE_HOST_STATE_ROOT/requested-packages.txt" > "$LATTICE_HOST_STATE_ROOT/packages-manualized-by-lattice.txt"
    else
        : > "$LATTICE_HOST_STATE_ROOT/packages-manualized-by-lattice.txt"
    fi
    rm -f "$LATTICE_HOST_STATE_ROOT/.manual-added.$$"
    chmod 0600 "$now" "$manual_now" "$LATTICE_HOST_STATE_ROOT/packages-added-by-lattice.txt" "$LATTICE_HOST_STATE_ROOT/packages-manualized-by-lattice.txt"
}

_lattice_restore_services() {
    local file="$LATTICE_HOST_STATE_ROOT/services-before.tsv"
    [[ -f "$file" ]] || return 0
    local unit load active enabled
    while IFS=$'\t' read -r unit load active enabled; do
        [[ -n "$unit" ]] || continue
        if [[ "$load" == "not-found" ]]; then
            systemctl disable "$unit" >/dev/null 2>&1 || true
            systemctl stop "$unit" >/dev/null 2>&1 || true
            continue
        fi
        case "$enabled" in
            enabled|enabled-runtime|static|indirect|generated|alias) systemctl enable "$unit" >/dev/null 2>&1 || true ;;
            *) systemctl disable "$unit" >/dev/null 2>&1 || true ;;
        esac
        if [[ "$active" == "active" ]]; then
            systemctl start "$unit" >/dev/null 2>&1 || true
        else
            systemctl stop "$unit" >/dev/null 2>&1 || true
        fi
    done < "$file"
}

_lattice_restore_packages() {
    local file="$LATTICE_HOST_STATE_ROOT/packages-added-by-lattice.txt"
    command -v apt-get >/dev/null 2>&1 || return 0
    if [[ ! -f "$file" && -f "$LATTICE_HOST_STATE_ROOT/packages-planned-by-lattice.txt" ]]; then
        local current="$LATTICE_HOST_STATE_ROOT/.packages-current.$$"
        local added="$LATTICE_HOST_STATE_ROOT/.packages-added.$$"
        dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | sort -u > "$current"
        comm -13 "$LATTICE_HOST_STATE_ROOT/packages-before.txt" "$current" > "$added"
        comm -12 "$added" "$LATTICE_HOST_STATE_ROOT/packages-planned-by-lattice.txt" > "$file"
        rm -f -- "$current" "$added"
        chmod 0600 "$file"
    fi
    [[ -s "$file" ]] || return 0
    mapfile -t managed < <(grep -E '^[A-Za-z0-9.+:-]+$' "$file" | sort -u)
    [[ "${#managed[@]}" -gt 0 ]] || return 0
    local simulation proposed unexpected=0 pkg
    simulation="$(DEBIAN_FRONTEND=noninteractive apt-get -s remove -y -- "${managed[@]}" 2>/dev/null || true)"
    mapfile -t proposed < <(printf '%s\n' "$simulation" | awk '/^Remv /{print $2}' | sort -u)
    for pkg in "${proposed[@]}"; do
        if ! printf '%s\n' "${managed[@]}" | grep -Fxq -- "$pkg"; then
            echo "WARNING: package rollback would remove non-Lattice package $pkg; leaving Lattice-added packages installed." >&2
            unexpected=1
        fi
    done
    [[ "$unexpected" -eq 0 ]] || return 1
    if [[ "${#proposed[@]}" -gt 0 ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq -- "${managed[@]}" || {
            echo "WARNING: could not completely restore Lattice-added package state." >&2
            return 1
        }
    fi
}

_lattice_restore_manual_marks() {
    local file="$LATTICE_HOST_STATE_ROOT/packages-manualized-by-lattice.txt"
    [[ -s "$file" ]] || return 0
    command -v apt-mark >/dev/null 2>&1 || return 1
    local pkg failed=0
    while IFS= read -r pkg; do
        [[ "$pkg" =~ ^[A-Za-z0-9.+:-]+$ ]] || continue
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -Fq 'install ok installed' || continue
        if ! apt-mark auto "$pkg" >/dev/null 2>&1; then
            echo "WARNING: could not restore automatic-install mark for $pkg" >&2
            failed=1
        fi
    done < "$file"
    return "$failed"
}


lattice_host_state_restore() {
    [[ -f "$LATTICE_HOST_STATE_MARKER" ]] || return 0
    local failed=0
    _lattice_restore_packages || failed=1
    _lattice_restore_manual_marks || failed=1
    _lattice_restore_services || failed=1
    return "$failed"
}
