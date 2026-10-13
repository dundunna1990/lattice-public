# Installation

This guide is written for a first-time Lattice user.

A **node** is simply a computer running Lattice. One node becomes the **Master** and the rest become **Workers**.

- **Master** — your main Lattice computer. It shows fleet-wide status and is where you add and manage Workers.
- **Worker** — another computer that joins the Master and becomes part of the fleet.

A simple three-computer setup looks like this:

```text
                  Main computer
                  Lattice Master
                       │
            ┌──────────┴──────────┐
            │                     │
        Laptop                 Mini PC
    Lattice Worker         Lattice Worker
```

## Before you start

Lattice v0.1 currently targets:

- Ubuntu
- Linux Mint
- NetworkManager-based networking
- normal IPv4 connectivity between the computers on the same trusted LAN

The installer provisions the packages and services Lattice needs, including Python, OpenSSH, Avahi, SSHFS, firewall support, and Lattice's own services.

Lattice is a **Public Alpha**. Use a non-critical machine or homelab first and keep independent backups of anything important.

## Important: use a Git clone

Lattice requires a complete Git checkout because the installer verifies tracked release files and Git metadata.

Do **not** use GitHub's **Download ZIP** button.

## Step 1 — install the Master

Start on the computer you want to use as your main Lattice machine.

Open a terminal and run:

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
sudo ./lattice-bootstrap.sh
```

The bootstrap installs Lattice and opens the first-time setup wizard.

When asked for the role, choose:

```text
Master
```

The Master is the computer that owns the fleet view and approves new Workers.

Complete the wizard. When Master setup finishes, leave that computer running and connected to the network.

## Step 2 — install the first Worker

Go to the second computer you want to add.

Run the same installation commands:

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
sudo ./lattice-bootstrap.sh
```

This time choose:

```text
Worker
```

The Worker finishes its local setup, starts its Lattice Worker service, and enters a short-lived pairing mode.

You will see a pairing screen with a code similar to:

```text
ABCD2345-EFGH67
```

Keep that screen open.

## Step 3 — add the Worker from the Master

Return to the Master.

Open Lattice:

```bash
lattice re-run
```

Choose:

```text
Add Computer
```

The Master scans the local network for Lattice Workers that are currently waiting to pair.

When your Worker appears:

1. Select the Worker.
2. Enter the **entire pairing code exactly as shown, including the dash**.
3. The Master sends a pairing request to that Worker.

## Step 4 — approve the request on the Worker

Return to the Worker.

The Worker will tell you that the Master has requested pairing.

During first-time setup, press:

```text
A
```

to approve the request locally.

That local approval is intentional: a network request alone is not allowed to enroll a Worker.

After approval, Lattice verifies the Worker and adds it to the fleet.

## Step 5 — let Lattice finish the Worker network assignment

As part of first-time pairing, the Master may assign the Worker its permanent Lattice network address.

If you are physically using the Worker, this normally happens in the background.

If you are installing the Worker through SSH, the address change may disconnect that SSH session. That is expected. Reconnect using the new Worker address if needed.

## Step 6 — repeat for more Workers

For every additional computer:

1. install Lattice
2. choose **Worker**
3. leave its pairing screen open
4. choose **Add Computer** on the Master
5. enter the pairing code
6. approve on the Worker

There is still only one Master.

## Step 7 — verify the fleet

On the Master, run:

```bash
lattice status
```

A healthy fleet should show the Master, the paired Workers, and no unexpected active alerts.

You can also reopen the main dashboard with:

```bash
lattice re-run
```

The dashboard shows fleet health, node connections, backups, Daily Care, alerts, and supported automation state.

## Headless Workers

A Worker does not need a monitor or desktop environment.

If the machine is headless, connect to it with ordinary SSH first:

```bash
ssh user@worker-address
```

Then run the same clone and bootstrap commands inside that SSH terminal:

```bash
git clone https://github.com/dundunna1990/lattice-public.git
cd lattice-public
sudo ./lattice-bootstrap.sh
```

The Lattice setup wizard runs inside the SSH terminal.

If the Worker receives a new network address during pairing, reconnect to that new address and continue if necessary.

## What the installer changes

Lattice is a system-management tool, so installation makes system-level changes.

Depending on the selected role and setup choices, the installer:

- installs the packages Lattice needs
- installs and starts Lattice services
- creates Lattice-managed service accounts and permissions
- prepares the SSH-based connections used for file access, trusted shell, and backups
- applies Lattice firewall rules required by the selected role
- records supported original network state so it can be restored later when requested

Lattice keeps normal administrative SSH separate from its managed file, trusted-shell, and backup connections.

## Running Lattice after setup

Open the TUI:

```bash
lattice re-run
```

Useful checks:

```bash
lattice status
lattice workers list
lattice shell status
lattice system status
```

See the [Operator Guide](OPERATOR_GUIDE.md) for an explanation of what the main areas do.

## Upgrading

Pull the desired revision, then rerun the installer:

```bash
git pull --ff-only
sudo ./deploy/install.sh
```

For Worker upgrades, use ordinary administrative SSH on port 22.

Do **not** perform a Worker upgrade through Lattice's managed trusted-shell connection because the installer restarts and updates Lattice-managed transports.

## Removing Lattice

For a normal full removal that also restores the original network settings Lattice recorded before setup:

```bash
sudo ./deploy/uninstall.sh --purge --restore-network
```

To fully remove Lattice but intentionally leave the machine's current network configuration in place:

```bash
sudo ./deploy/uninstall.sh --purge --keep-network
```

After uninstalling, verify the machine's normal network connection before closing your recovery terminal or SSH session.

## If something goes wrong

Start with:

```bash
lattice status
lattice system status
systemctl --failed
```

Then see [Troubleshooting](TROUBLESHOOTING.md).

If setup stopped safely, do not bypass the safety check just to force the install through. Fix the reported condition and rerun the supported setup path.
