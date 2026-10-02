# Installation

## Requirements

Lattice version 1 supports Ubuntu and Linux Mint systems using NetworkManager. Participating computers need normal IPv4 LAN connectivity. The installer provisions the required Python, OpenSSH, Avahi, SSHFS, firewall, and supporting packages.

## Clone

Lattice installation requires a complete Git checkout because the installer stages only tracked release files and verifies the checkout boundary. Do not use GitHub's Download ZIP feature.

```bash
git clone <repository-url>
cd lattice-public
```

## Install and initialize a node

The recommended fresh-install entry point is:

```bash
sudo ./lattice-bootstrap.sh
```

This runs the release installer and then launches the first-time setup wizard.

The equivalent two-step form is:

```bash
sudo ./deploy/install.sh
sudo lattice init
```

The setup wizard detects the active interface, gateway, subnet, and DNS settings instead of assuming a particular home-LAN address range. Use the wizard to choose the local role and complete setup/pairing.

## Upgrade

Pull the desired revision, then rerun the installer:

```bash
git pull --ff-only
sudo ./deploy/install.sh
```

For Worker upgrades, use ordinary administrative SSH on port 22. Do not perform an upgrade through Lattice's managed trusted-shell transport because the installer restarts that transport.

## Verify

Useful checks:

```bash
lattice status
lattice system status
systemctl --failed
```
