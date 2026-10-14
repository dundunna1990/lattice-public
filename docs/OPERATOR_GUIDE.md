# Operator Guide

This guide explains what Lattice is showing you after the fleet is installed and paired.

## The basic idea

A **node** is one computer running Lattice.

- The **Master** is the main computer where you see and manage the fleet.
- A **Worker** is another computer that has been paired to the Master.
- A fleet can have one Master and one or more Workers.

Open the Lattice terminal interface with:

```bash
lattice re-run
```

The interface changes depending on the role of the machine.

- On the **Master**, you see fleet-wide status and controls.
- On a **Worker**, you see local status and local actions for that Worker.

## What the Master dashboard is telling you

The Master dashboard is designed to answer a few simple questions:

- Are all of my Lattice computers online?
- Is each node healthy?
- Are file connections working?
- Is trusted shell connectivity working?
- Are backups healthy?
- Did Daily Care run successfully?
- Are there active alerts?
- Is automatic recovery available or blocked?

You do not need to understand every internal service to use the dashboard.

## Nodes

The node list represents the computers that currently belong to the fleet.

A healthy Worker should normally show recent contact with the Master and healthy connection state.

If a Worker is sleeping, disconnected from Wi-Fi, powered off, or otherwise unreachable, Lattice may show it as unavailable until it returns.

## Adding another computer

To add a new Worker:

1. install Lattice on the new computer
2. choose **Worker** during setup
3. leave the Worker on its pairing screen
4. open Lattice on the Master
5. choose **Add Computer**
6. select the discovered Worker
7. enter the pairing code shown on the Worker
8. approve the request locally on the Worker

The Master scans for Workers that are actively waiting to pair. It does not enroll arbitrary computers just because they are visible on the network.

See [Installation](INSTALLATION.md) for the full walkthrough.

## Removing and re-adding a Worker

Removing a Worker is a trust-revocation operation, not just removing it from the dashboard.

On a successful removal, Lattice:

1. verifies that the Worker's current Master pairing credentials have been revoked locally
2. publishes a new signed fleet generation that no longer includes that Worker as an active member
3. records the removed node identity as revoked in fleet state
4. rebuilds managed file and trusted-shell access from the remaining active fleet

This means the removed Worker is no longer authorized by the managed file or trusted-shell transports on the remaining nodes as they reconcile the new fleet state.

Backup access is separate from file and shell access. Backup authorization is generated from its own signed assignment state, and only active fleet members are included. After a Worker is revoked, the next backup assignment generation drops any remote assignment for that node; target-side reconciliation then removes the stale backup authorization and its Lattice-managed backup transport account. Because backup assignment reconciliation runs separately, that cleanup can follow the fleet revocation rather than happen at exactly the same instant.

Firewall rules behave differently. Lattice's managed firewall rules are LAN-scoped service rules, not per-node trust entries. Removing one Worker therefore does not remove the Lattice service ports from every other node. Those rules remain part of the installed Lattice service configuration until the relevant uninstall or firewall-restore path removes them.

A permanent node ID is the machine's identity, not a credential that grants access by itself. If the **same Lattice installation** is added back later, it can keep the same permanent node ID, but it must still complete a fresh pairing code, local approval, and signed fleet activation before trust is restored. A different machine receives a different node ID and does not inherit the removed machine's trust.

## File access

Lattice can make another active node's Home files available through a dedicated file connection.

Peer Home directories are **intentionally read/write**. Writing through a peer mount **changes that peer's real Home directory**.

That means this behaves like real remote file access, not like a copy or a backup.

Use backups for recovery. Use peer file access when you intentionally want to work with files on another computer.

## Trusted shell / SSH

Lattice maintains a dedicated trusted shell connection between active fleet members.

In plain terms, this is the managed SSH path Lattice uses for supported fleet connectivity and recovery-related functions.

It is separate from normal administrative SSH.

For normal machine administration, upgrades, or manual recovery work, continue to use ordinary SSH on port 22.

You can inspect trusted shell state with:

```bash
lattice shell status
```

## Backups

Lattice uses Restic and a source-owned backup model.

That means the computer being backed up reads its own files and sends them directly to its assigned backup destination.

The Master keeps track of assignments and backup health, but the backup data does not need to flow through the Master first.

The dashboard shows backup state per node so you can quickly see whether a backup is healthy, not configured, paused, or needs attention.

Restores are staged before final placement to reduce the chance of accidentally overwriting live data.

See [Backup and Recovery](BACKUP_AND_RECOVERY.md) for the detailed backup model.

## Daily Care

Daily Care runs locally on each node.

It checks for conditions such as:

- disk pressure
- failed services
- package problems
- memory pressure
- temperature
- battery state where available
- reboot-required state

It can also perform a limited set of conservative maintenance actions when its safety checks allow them.

Daily Care does not blindly delete personal files, projects, browser data, containers, virtual machines, or backups to recover disk space.

You can run Daily Care locally from the TUI.

The Master can display Worker Care results, but scheduled Daily Care runs locally on each node rather than the Master remotely cleaning every Worker.

See [Daily Care](DAILY_CARE.md) for details.

## Auto-Heal

Auto-Heal is deliberately limited.

Lattice can automatically attempt only a small set of known repairs that have explicit safety rules.

If Lattice cannot prove an automatic action is allowed and safe, it does not guess. It either leaves the problem visible or stops the repair attempt and requires attention.

The dashboard may show whether Auto-Heal is automatic, alert-only, blocked by Dry Run, or stopped by a circuit breaker after repeated failures.

## Alerts

Alerts tell you that Lattice found something that currently needs attention or that a previous problem has not yet been proven resolved.

Lattice prefers to resolve alerts from fresh evidence rather than simply deleting history.

Useful commands:

```bash
lattice alerts list
lattice alerts get <id>
```

## Fleet verification

Lattice can verify the current fleet and clear only state that has been proven stale or resolved.

This is intentionally conservative.

If an active node is unreachable, authentication fails, or Lattice sees a condition it does not know how to prove safe, verification blocks rather than clearing it anyway.

## Useful commands

These are the main read-only commands most operators need:

```text
lattice status
lattice workers list
lattice mounts fleet
lattice shell status
lattice alerts list
lattice events
lattice services list
lattice system status
lattice autoheal status
```

Fleet-wide commands are available on the Master. A Worker refuses Master-only fleet commands.

## If a node looks unhealthy

Start with:

```bash
lattice status
lattice system status
```

On the Master, also check:

```bash
lattice workers list
lattice shell status
lattice alerts list
```

Then use [Troubleshooting](TROUBLESHOOTING.md).

Do not bypass a Lattice safety stop just to make a warning disappear. The intended path is to identify the current problem, correct it, and then let Lattice verify the recovery.
