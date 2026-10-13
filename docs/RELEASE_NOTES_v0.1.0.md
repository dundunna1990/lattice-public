# Lattice v0.1.0 — Initial Public Release

Lattice v0.1.0 is the first public alpha release of Lattice, a Linux LAN fleet manager for small trusted groups of Ubuntu and Linux Mint computers.

## Included

- Master/Worker fleet management
- signed fleet membership state
- persistent peer file access
- dedicated trusted shell connectivity
- health monitoring
- bounded auto-heal
- NetworkManager reconciliation
- source-owned Restic backups
- staged restore workflows
- encrypted recovery-kit support
- Daily Care maintenance and health checks
- curses TUI and CLI
- read-only operator surfaces
- Python 3.10, 3.11, and 3.12 CI coverage

## Supported environment

This release is intended for:

- Ubuntu and Linux Mint
- NetworkManager-based networking
- small trusted LAN fleets
- technically comfortable operators

## Project status

**Public Alpha — not production-ready.** Lattice is running on a real small multi-machine fleet, but bugs, rough edges, and incomplete qualification are expected. Do not treat v0.1.0 as problem-free or suitable for critical systems. Test it in a non-critical environment first and keep independent backups of important data.

## What this release is for

This release is intended for testing, homelab use, feedback, and contribution while reliability and polish continue to improve. See [Known limitations](KNOWN_LIMITATIONS.md) before relying on Lattice for anything important.

## Install

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
sudo ./lattice-bootstrap.sh
```

GitHub's Download ZIP path is not supported because the installer requires Git metadata.

## License

Apache License 2.0.
