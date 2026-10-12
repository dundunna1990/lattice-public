# Daily Care

Daily Care is Lattice's conservative local maintenance and health subsystem. It runs independently on each node.

## Health Status

Care reports `HEALTHY`, `ATTENTION`, `CRITICAL`, `STALE`, or `OFF`.

Current health checks include root disk and inode pressure, failed systemd units, reboot-required state, dpkg audit results, memory pressure, temperatures, and battery state where available.

## Safe Maintenance

Allowed automatic maintenance includes APT autoclean, bounded journal cleanup, stale crash-report cleanup, unused Flatpak runtime cleanup, guarded old-kernel removal, and security-only updates when policy can be proven safe.

Before automatic security updates, Daily Care verifies that dpkg --audit is clean. If the package manager is already incomplete or broken, updates are deferred and the node is marked for attention instead of attempting further package changes. The Care service permits package-managed kernel module updates because Ubuntu security updates can legitimately update /usr/lib/modules.

A historical NetworkManager-wait-online.service failure is suppressed only when NetworkManager is currently active and nm-online confirms the machine is online; active networking failures remain visible.

## Protected Data

Daily Care never deletes data under `/home` or `/root`. It does not clean browser profiles, credentials, projects, personal files, peer mounts, backup repositories, containers, or virtual-machine data.

## Scheduling

The timer runs daily at 03:17 with up to 45 minutes of randomized delay and `Persistent=true`.

On an unplugged laptop below the configured battery threshold, Care still performs health scanning but defers heavier maintenance.

Care also defers mutation while Lattice backup/restore work is active.
