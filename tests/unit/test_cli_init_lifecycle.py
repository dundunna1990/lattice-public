from types import SimpleNamespace

import curses

from lattice.cli import main as cli_main
from lattice.wizard import lifecycle


def test_init_failure_does_not_enter_tui(monkeypatch):
    entered = []
    monkeypatch.setattr(curses, "wrapper", lambda _func: False)
    monkeypatch.setattr(cli_main, "_run_main_tui", lambda: entered.append(True) or 0)

    assert cli_main.cmd_init(SimpleNamespace()) == 1
    assert entered == []


def test_successful_master_init_enters_existing_tui(monkeypatch):
    monkeypatch.setattr(curses, "wrapper", lambda _func: True)
    monkeypatch.setattr(lifecycle, "current_role", lambda: "master")
    monkeypatch.setattr(cli_main.os.path, "exists", lambda path: path == cli_main.CONFIG_PATH)
    monkeypatch.setattr(cli_main, "_run_main_tui", lambda: 73)

    assert cli_main.cmd_init(SimpleNamespace()) == 73
