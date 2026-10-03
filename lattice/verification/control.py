"""Narrow privileged entry point for fleet verification controls."""
from __future__ import annotations

import json
import os
import sys

from lattice.verification.fleet import clear_proven_resolved, verify_fleet
from lattice.verification.node import VerificationError, clear_local_resolved_state


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Lattice verification control must run as root")
    args = sys.argv[1:]
    if args == ["verify-fleet"]:
        result = verify_fleet()
    elif args == ["clear-resolved"]:
        result = clear_proven_resolved()
    elif args == ["clear-local"]:
        try:
            result = clear_local_resolved_state()
        except VerificationError as exc:
            result = {"status": "blocked", "error": str(exc)}
    else:
        raise SystemExit(
            "usage: lattice-verification-control "
            "{verify-fleet|clear-resolved|clear-local}"
        )
    print(json.dumps(result, sort_keys=True))
    if result.get("status") == "blocked" or result.get("clear_status") == "blocked":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
