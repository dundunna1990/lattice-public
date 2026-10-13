# Known Limitations

Lattice v0.1.0 is a **public alpha**. It is usable for testing and small trusted homelab-style fleets, but it is **not production-ready** and should not be treated as problem-free software.

## Current limitations

- **Limited real-machine qualification** — normal CI does not cover every destructive, power-loss, interrupted-update, restore, networking, or hardware failure mode.
- **Supported environment is narrow** — Ubuntu and Linux Mint with NetworkManager are the qualified targets. Other distributions and network stacks may not work.
- **Local name discovery matters** — some authenticated operations still depend on `.local`/mDNS resolution even when a known worker IP is available.
- **Retry/idempotency hardening is incomplete** — mutating requests use client idempotency keys, but server-side deduplication is not yet enforced everywhere.
- **Audit-chain startup handling is still being improved** — invalid audit-chain state is detected by the audit subsystem, but startup degraded-state handling is not yet as explicit as intended.
- **Optional notification integrations still need hardening** — some non-core notification paths are not ready for broad exposure and are not part of the recommended first-time setup.
- **Installer coverage is still expanding** — clean-install behavior is tested and improved continuously, but not every minimal OS/hardware combination has been qualified.
- **Restore and recovery paths deserve caution** — restore safety has been hardened, but interruption and recovery scenarios should still be tested in your own environment before relying on them for important data.
- **Operator polish is ongoing** — rough edges, stale status displays, and confusing error presentation may still appear.

## Recommended use

Good current use cases:

- homelab experimentation
- small trusted LAN fleets
- testing and feedback
- development and contribution
- learning how Lattice behaves before depending on it

Avoid treating v0.1.0 as suitable for:

- critical production infrastructure
- irreplaceable data without independent backups
- unattended operation where recovery access is unavailable
- large or hostile networks
- unsupported distributions or network stacks

## Reporting issues

If you find a bug or confusing behavior, please open an issue with:

- what you expected
- what actually happened
- the relevant command or screen
- OS/distribution version
- whether the machine is Master or Worker
- logs or screenshots with private information removed

For security-sensitive findings, read [Security](SECURITY.md) before posting details publicly.
