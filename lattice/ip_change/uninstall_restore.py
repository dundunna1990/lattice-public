"""Restore the exact NetworkManager snapshot saved before Lattice set a static IP."""
from lattice.ip_change.setup import StaticIPError, restore_connection, snapshot_connection
from lattice.ip_change.state import (
    read_original_network_state,
    read_state,
)


_PROFILE_FIELDS = (
    "ipv4.method",
    "ipv4.addresses",
    "ipv4.gateway",
    "ipv4.dns",
)


def _restore_source():
    original = read_original_network_state()

    if original is not None:
        snapshot = original.get("snapshot")
        interface = original.get("interface")

        if not snapshot or not interface:
            raise StaticIPError(
                "The saved pre-Lattice network snapshot is incomplete"
            )

        return snapshot, interface

    state = read_state()

    if (
        not state
        or not state.get("snapshot")
        or not state.get("interface")
    ):
        raise StaticIPError(
            "No verified pre-Lattice network snapshot is available"
        )

    # In old installations, previous_expected=None means this was
    # the first Lattice network change, so its transaction snapshot
    # is still a legitimate pre-Lattice baseline.
    if state.get("previous_expected") is not None:
        raise StaticIPError(
            "The original pre-Lattice network snapshot is unavailable; "
            "refusing to restore an intermediate Lattice static configuration"
        )

    return state["snapshot"], state["interface"]


def restore_saved_network() -> None:
    snapshot, interface = _restore_source()

    connection = snapshot.get("connection")
    if not connection:
        raise StaticIPError(
            "The saved pre-Lattice network snapshot has no connection name"
        )

    restore_connection(snapshot, interface)

    restored = snapshot_connection(connection)
    mismatches = []

    for field in _PROFILE_FIELDS:
        expected = str(snapshot.get(field, "")).strip()
        actual = str(restored.get(field, "")).strip()
        if actual != expected:
            mismatches.append(
                f"{field}: expected {expected!r}, got {actual!r}"
            )

    if mismatches:
        raise StaticIPError(
            "Pre-Lattice network restore verification failed: "
            + "; ".join(mismatches)
        )


if __name__ == "__main__":
    restore_saved_network()
