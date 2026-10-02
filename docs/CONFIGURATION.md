# Configuration

Primary configuration is stored in `/etc/lattice/lattice.toml`. Runtime state is stored separately in SQLite.

## Important Defaults

| Area | Default |
| --- | --- |
| Health poll interval | 10 seconds |
| Master API port | 8080 |
| Worker API/pairing port | 9999 |
| File transport port | 22022 |
| Trusted shell port | 22023 |
| Backup schedule hour | 02:00 |
| Backup retention | 30 daily / 26 weekly / 12 monthly |
| Backup free-space reserve | 20% |
| Daily Care disk warning | 80% |
| Daily Care disk critical | 90% |
| Daily Care low-battery defer | below 30% |

Daily Care is enabled by default. Security updates, APT autoclean, journal vacuuming, stale crash cleanup, unused Flatpak runtime cleanup, and guarded old-kernel cleanup are enabled by default.

## Runtime Overrides

Installed services use canonical Lattice paths. Test-only or non-canonical path overrides are rejected in an installed runtime.

Use the TUI or supported CLI configuration paths rather than editing runtime SQLite directly.
