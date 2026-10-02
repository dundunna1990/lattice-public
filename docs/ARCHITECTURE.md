# Architecture

## Roles

A Lattice fleet has one Master and one or more Workers.

The Master owns signed fleet membership and desired state. Workers maintain local authoritative observations and report health back to the Master.

Node identity is based on a permanent node ID. IP addresses are locators and may change.

## Network Channels

Default channels are separated by purpose:

| Purpose | Port |
| --- | ---: |
| Administrative/recovery SSH | 22 |
| Master API | 8080 |
| Worker API/pairing | 9999 |
| Peer file transport | 22022 |
| Trusted shell | 22023 |
| Backup SFTP | 22024 |

## State

Static configuration and secrets live in protected configuration/key stores. SQLite stores runtime state, observations, events, alerts, and subsystem state.

## File Access

Each node exposes its Home through a dedicated SSH transport. Mount management reconciles persistent peer mounts and reports their state.

## Backup

Backup is source-owned: the source node runs Restic directly against the assigned target. The Master coordinates assignment and observation but is not in the backup data path.
