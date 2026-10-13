# Lattice

**Manage a small group of Linux computers from one main machine.**

Lattice is an open-source Linux fleet manager for small trusted networks. Install it on each Ubuntu or Linux Mint computer you want to manage, choose one computer as the **Master**, and make the others **Workers**.

A **node** simply means a computer running Lattice. After the nodes are paired, the Master gives you one place to see fleet health, reach files, use trusted SSH connections, watch backups, check maintenance, and see when something needs attention.

> **Current status: Public Alpha — not production-ready.** Lattice is actively being tested and polished. It runs on a real small multi-machine fleet, but bugs, rough edges, and incomplete qualification should be expected. Do **not** treat v0.1.0 as problem-free, enterprise-ready, or appropriate for critical systems. Test it in a non-critical environment first and keep independent backups of anything important.

## How Lattice works

A Lattice fleet has one Master and one or more Workers.

```text
                  Your main computer
                   Lattice Master
                        │
             ┌──────────┴──────────┐
             │                     │
         Laptop                 Mini PC
     Lattice Worker         Lattice Worker
```

- **Master** — the main computer you use to view and manage the fleet.
- **Worker** — another computer that joins the Master and becomes part of the fleet.
- **Node** — any computer running Lattice, including the Master.

For example, a desktop, laptop, and mini PC running Lattice would be a **three-node fleet**: one Master and two Workers.

Workers are paired to the Master with a short-lived pairing code and a local approval step on the Worker. Lattice keeps a permanent identity for each node, so an IP address is treated as where a computer currently is on the network, not as the computer's identity.

## What you can do

### See the whole fleet from one place

The Master dashboard shows which computers are healthy, which are online, whether file and shell connections are working, backup state, Daily Care state, alerts, and supported automation status.

![Lattice terminal fleet dashboard](docs/assets/lattice-tui.png)

### Access files between your computers

Lattice can make a paired computer's Home files available from another node, so you do not have to manually build separate file-sharing arrangements for every machine.

Peer Home mounts are **intentionally read/write**. Writing through a peer mount **changes that peer's real Home directory**. Treat this as real remote file access, not as a backup.

### Connect to another computer's terminal

Lattice sets up and maintains a dedicated trusted SSH connection between active fleet members. This gives the fleet a managed shell connection for supported Lattice operations while keeping ordinary administrative SSH separate.

Normal port-22 SSH is still the right path for normal administration and software upgrades.

### Back up one computer to another

Lattice uses Restic for backups. The computer being backed up reads its own data and sends it directly to its assigned backup target; the Master coordinates the assignment and watches backup state without carrying the backup data itself.

Backups use a separate protected connection from file access and trusted shell access. Restores are staged first instead of blindly writing restored data directly into a live Home directory.

### Daily Care

Each node can check itself for conditions such as disk pressure, failed services, package problems, memory pressure, temperature, battery state where available, and whether a reboot is required.

Daily Care can also perform a limited set of conservative maintenance tasks. It does **not** delete personal Home files, projects, browser data, containers, virtual machines, or backup repositories just to make space.

### Limited automatic recovery

Lattice can automatically recover from a deliberately small set of problems it knows how to handle safely. It does not have unrestricted permission to run arbitrary repair commands.

If repeated repair attempts fail, a safety gate blocks the action, or Lattice cannot prove a repair is safe, it stops and reports the problem instead of guessing.

### Network and node tracking

Lattice tracks each node by a permanent node identity rather than trusting an IP address as identity. Supported NetworkManager changes can be detected and reconciled while the Master keeps track of the current route to each active Worker.

## Getting started

Lattice installation requires a real Git checkout. GitHub's **Download ZIP** is not supported because the installer verifies tracked release files and Git metadata.

### 1. Pick your Master

Start on the computer you want to use as your main Lattice machine.

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
sudo ./lattice-bootstrap.sh
```

The installer opens the guided setup wizard. Choose **Master**.

### 2. Install Lattice on a Worker

On the next computer you want to add, run the same commands:

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
sudo ./lattice-bootstrap.sh
```

Choose **Worker**.

The Worker starts its pairing process, waits for the Master, and displays a pairing code.

### 3. Add the Worker from the Master

On the Master, open Lattice:

```bash
lattice re-run
```

Choose **Add Computer**. The Master scans the local network for Lattice Workers that are waiting to pair.

Select the Worker and enter the **entire pairing code exactly as shown, including the dash**.

### 4. Approve on the Worker

Return to the Worker and approve the pending request. During first-time setup, the Worker screen tells you when to press **A** to approve.

Lattice then verifies the Worker and adds it to the fleet.

> During pairing, Lattice may assign the Worker its permanent Lattice network address. If you are installing through SSH and that address changes, the SSH session may disconnect. Reconnect using the Worker's new address if needed.

### 5. Repeat for more Workers

Repeat the Worker install and pairing steps for each additional computer.

When finished, check the fleet from the Master:

```bash
lattice status
```

or open the dashboard again with:

```bash
lattice re-run
```

For the full walkthrough, see [Installation](docs/INSTALLATION.md).

## Headless Workers are supported

A Worker does not need a monitor or desktop environment. If you can SSH into the machine, you can install Lattice through that terminal:

```bash
ssh user@worker-address
```

Then clone the repository and run the same bootstrap command shown above. The curses setup wizard works inside the SSH terminal.

## What the installer changes

Lattice is a system-management tool, so the installer does more than copy an application into your Home directory.

Depending on the role and setup choices, it installs the required packages and Lattice services, creates Lattice-managed service accounts and permissions, prepares the dedicated SSH-based connections used by Lattice, applies the Lattice firewall rules needed for the selected role, and records supported network state so setup and removal can be handled safely.

If you are testing Lattice, use a non-critical machine or lab first.

## Supported systems

Lattice v0.1 currently targets:

- Ubuntu
- Linux Mint
- NetworkManager-based networking
- normal IPv4 LAN connectivity
- Python 3.10–3.12

Other distributions and network stacks are not currently qualified.

## Removing Lattice

From the cloned Lattice repository, a full removal that also restores the original network configuration recorded during setup is:

```bash
sudo ./deploy/uninstall.sh --purge --restore-network
```

If you intentionally want to keep the machine's current network configuration instead:

```bash
sudo ./deploy/uninstall.sh --purge --keep-network
```

Read the prompts and verify the machine's network state after removal.

## Safety model

Lattice deliberately favors **safe-stop and bounded repair** over aggressive automation.

Examples:

- Daily Care refuses maintenance when its safety checks cannot prove the action is within policy.
- Worker privilege elevation is limited to narrow root-owned helpers.
- Restore operations use staged placement and explicit conflict handling.
- Fleet membership state is signed.
- Dedicated SSH transports use strict host-key verification.
- Real-machine destructive tests are opt-in rather than part of normal test runs.
- Normal status reads use a **read-only operator interface** separated from the privileged operations that make system changes.

The dedicated file, trusted-shell, backup, pairing, and recovery paths are intentionally kept separate rather than sharing one unrestricted credential or control path.

## Good fit for

Lattice is intended for people who run a **small trusted Linux fleet**, such as:

- a homelab
- several household Linux computers
- a workshop or small office
- a personal development/test fleet
- a few headless and desktop machines on the same trusted LAN

It is **not** intended to replace enterprise MDM, Kubernetes, Active Directory, or large-scale configuration-management systems.

## Documentation

New to Lattice? Start here:

- [Installation](docs/INSTALLATION.md) — step-by-step Master, Worker, and pairing setup
- [Operator guide](docs/OPERATOR_GUIDE.md) — what to do after the fleet is running
- [Known limitations](docs/KNOWN_LIMITATIONS.md) — current Public Alpha limitations

More detailed reference:

- [Documentation index](docs/README.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Backup and recovery](docs/BACKUP_AND_RECOVERY.md)
- [Daily Care](docs/DAILY_CARE.md)
- [Security](docs/SECURITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Testing

The repository includes unit, integration, and opt-in real-machine E2E tests.

Normal CI currently runs against Python 3.10, 3.11, and 3.12. Real-machine destructive tests require explicit environment configuration and safety gates; they are intentionally excluded from ordinary CI.

Passing CI means the tested code paths passed the automated suite. It does **not** mean every install, network failure, restore interruption, distribution variant, or hardware environment has been qualified.

## Project stage

Lattice is currently **v0.1.0 / Public Alpha**.

This release is for **testing, feedback, homelab experimentation, and contribution**. It is not being presented as finished or production-ready software.

Known areas still being improved include:

- broader clean-install and distribution qualification
- real-machine interruption and recovery testing
- network fallback behavior when local name discovery is unavailable
- additional request/retry and authorization hardening
- operator polish, documentation, and error handling

See [Known limitations](docs/KNOWN_LIMITATIONS.md) for the current public limitations summary.

Bug reports and technically detailed feedback are welcome.

## Contributing

Lattice is open source under the **Apache License 2.0**.

If you want to contribute, start by opening an issue describing the problem, proposed change, or test case. For code changes, keep fixes focused and include regression coverage when practical.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright 2026 Lattice contributors.

Licensed under the [Apache License 2.0](LICENSE).
