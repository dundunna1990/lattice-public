"""Narrow human-triggered Daily Care control."""

import os
import sys

from lattice.care.runner import CareRunError, run_daily_care


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Daily Care control must run as root")
    if sys.argv[1:] != ["run"]:
        raise SystemExit("usage: lattice-care-control run")
    try:
        result = run_daily_care(trigger="manual")
    except CareRunError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Daily Care finished: {result['status']}")


if __name__ == "__main__":
    main()
