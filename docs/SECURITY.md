# Security

Lattice is designed for a small trusted LAN, but it still separates identities, transports, privileges, and operator access.

## Operator Boundary

Human operators use a read-only operator interface separate from the privileged Master socket. Membership in `lattice-operator` does not grant arbitrary database, token, filesystem, or root access.

Privileged helpers are root-owned and expose narrow fixed operations through sudoers rules.

## Transport Separation

Administrative SSH, file access, trusted shell, and Backup SFTP use separate channels and identities. Backup keys are distinct from other transport keys.

## Identity

Fleet membership is signed. Permanent node IDs identify nodes; IP addresses are only current routes.

A node ID is an identity, not an authorization credential by itself. Access is granted by the current signed fleet and transport state.

## Revocation and Re-enrollment

A successful Worker removal publishes a new signed fleet generation with that Worker revoked. File and trusted-shell authorization are derived from active fleet membership, so their managed authorization and host-trust state are reconciled against the new generation.

Backup transport is intentionally separate. Remote backup authorization comes from a separately signed backup assignment generation. Revoked nodes are excluded when that assignment is rebuilt, and target-side reconciliation removes stale Lattice-managed backup keys, accounts, and chroot bindings when the newer assignment is applied.

The normal removal path also verifies revocation of the Worker's current Master pairing credential before completing Master-side removal.

Firewall rules are not node identities or credentials. Lattice's managed firewall openings are scoped to the configured local LAN and service ports, so removing one Worker does not delete those rules from other nodes.

Re-enrollment never restores trust merely because a familiar node ID appears again. The same installation may retain its permanent node ID, but it must complete a fresh pairing code, local approval, and signed activation. A different machine receives a different node ID and cannot inherit the old node's trust.

## Runtime Hardening

Systemd units use sandboxing and privilege-reduction settings where compatible, including `NoNewPrivileges` and protected kernel/control-group settings for sensitive oneshot services.

## Operational Guidance

Keep host keys and recovery credentials protected, use ordinary port-22 SSH for software upgrades, and do not bypass host-key verification when a node changes address. Verify the node's key before accepting a new address.
