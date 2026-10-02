"""Recover an interrupted network transaction during boot."""

import json
import logging

from lattice.ip_change.setup import restore_connection
from lattice.ip_change.state import (
    clear_expected_network,
    quarantine_state_file,
    read_state,
    write_expected_network,
    write_state,
)


logger = logging.getLogger(__name__)
_INCOMPLETE = {"prepared", "applying", "verifying", "reverting"}


def boot_recovery(runner=None):
    try:
        state = read_state()
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        RuntimeError,
        ValueError,
    ) as exc:
        try:
            quarantined = quarantine_state_file()
        except Exception as quarantine_exc:
            raise RuntimeError(
                "Saved network recovery state is corrupt and "
                "could not be quarantined safely: "
                f"{quarantine_exc}"
            ) from exc

        location = (
            str(quarantined)
            if quarantined is not None
            else "unknown"
        )

        raise RuntimeError(
            "Saved network recovery state is corrupt. "
            "No network change was attempted. "
            f"The original state was preserved at {location}."
        ) from exc

    if (
        not state
        or state.get("status") not in _INCOMPLETE
    ):
        return False

    interface = state.get("interface")
    snapshot = state.get("snapshot")
    if not interface or not snapshot:
        state["status"] = "recovery_failed"
        state["recovery_error"] = "The saved interface or connection snapshot is missing."
        write_state(state)
        raise RuntimeError(state["recovery_error"])

    try:
        if runner is None:
            restore_connection(snapshot, interface)
        else:
            restore_connection(snapshot, interface, runner)
        previous_expected = state.get("previous_expected")
        if previous_expected is None:
            clear_expected_network()
        else:
            write_expected_network(previous_expected)
    except Exception as exc:
        state["status"] = "recovery_failed"
        state["recovery_error"] = str(exc)
        write_state(state)
        raise

    state["status"] = "recovered"
    write_state(state)
    logger.warning("Recovered the previous NetworkManager settings after an interrupted change")
    return True


def main():
    boot_recovery()


if __name__ == "__main__":
    main()
