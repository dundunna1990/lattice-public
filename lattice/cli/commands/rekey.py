from types import SimpleNamespace

from lattice.cli.commands.workers import cmd_workers


def cmd_rekey(args) -> int:
    """Enforce the safe rotation workflow: revoke one peer, then re-pair it."""
    if args.all:
        print("Bulk credential rotation is refused. Rotate and verify one worker at a time.")
        return 1
    if not args.peer:
        print("Specify one worker hostname to rotate.")
        return 1
    print(
        f"Rotation for '{args.peer}' revokes its current token and SSH authorization first. "
        "The worker must then be put into pairing mode again."
    )
    result = cmd_workers(SimpleNamespace(action="remove", hostname=args.peer))
    if result != 0:
        print("Rotation stopped before re-pairing; existing master records were preserved.")
        return result
    print("Old credentials are revoked. Run 'lattice workers add' to issue a new worker token.")
    return 0
