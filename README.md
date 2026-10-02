# Lattice

Lattice is a Linux LAN mesh manager for a small trusted fleet of computers. It provides one Master node with multiple Worker nodes, persistent peer file access, trusted shell connectivity, health monitoring, bounded auto-heal, source-owned backups, and local Daily Care.

## Highlights

- Master/Worker fleet management with signed membership state
- Peer Home mounts are intentionally read/write over a dedicated file transport; writing through a peer mount changes that peer's real Home directory
- Trusted shell connectivity between paired nodes
- Automatic network reconciliation and health monitoring
- Bounded, policy-driven auto-heal
- Source-owned Restic backups to another Lattice node
- Staged restore workflow and encrypted recovery-kit support
- Daily Care for conservative maintenance and health checks
- Curses-based operator TUI plus CLI commands
- A read-only operator interface with narrow privilege boundaries for operator actions

## Supported systems

Lattice version 1 supports **Ubuntu and Linux Mint systems using NetworkManager**.

## Install

Use a real Git clone. The installer intentionally requires Git metadata, so GitHub's **Download ZIP** is not a supported installation method.

```bash
git clone <repository-url>
cd lattice-public
sudo ./lattice-bootstrap.sh
```

The bootstrap installs the current release and immediately opens the guided setup wizard. Choose one computer as the Master and the others as Workers.

After setup, open the operator interface with:

```bash
lattice re-run
```

## Documentation

Start with [docs/README.md](docs/README.md). Installation details are in [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Real-machine E2E tests

The E2E suite is included, but it has **no built-in hostnames, usernames, or fleet addresses**. Real-machine tests are opt-in and require explicit environment configuration. See the test safety gates in `tests/e2e/conftest.py`.
