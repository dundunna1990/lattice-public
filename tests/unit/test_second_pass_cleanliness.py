"""Fresh second-pass dead-reference regressions."""

from pathlib import Path


def test_removed_dead_cli_stubs_stay_removed() -> None:
    assert not Path(
        "lattice/cli/commands/rescue.py"
    ).exists()

    assert not Path(
        "lattice/cli/commands/emergency_shell.py"
    ).exists()

    assert not Path(
        "tests/conftest.py.bak"
    ).exists()


def test_deleted_runtime_modules_have_no_live_references() -> None:
    # Build these dynamically so this regression test does not itself
    # contain the stale fully-qualified module references it is searching for.
    deleted = (
        ".".join(("lattice", "api", "routes", "actions")),
        ".".join(("lattice", "healing", "action_queue")),
        ".".join(("lattice", "worker", "action_poller")),
        ".".join(("lattice", "cli", "commands", "bootstrap")),
    )

    roots = (
        Path("lattice"),
        Path("deploy"),
        Path("tests"),
    )

    for root in roots:
        for path in root.rglob("*"):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or path.suffix == ".pyc"
            ):
                continue

            text = path.read_text(
                encoding="utf-8",
                errors="ignore",
            )

            for name in deleted:
                assert name not in text, (
                    f"{path} still references {name}"
                )
