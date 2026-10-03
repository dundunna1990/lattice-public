"""Fleet-wide read-only verification and guarded resolved-state clearing."""

from lattice.verification.fleet import clear_proven_resolved, verify_fleet

__all__ = ["verify_fleet", "clear_proven_resolved"]
