from pathlib import Path
import curses

from lattice.wizard import screens


class FakeScreen:
    def __init__(self, keys):
        self.keys = iter(keys)
        self.erase_calls = 0
        self.refresh_calls = 0
        self.writes = []

    def getmaxyx(self):
        return (24, 80)

    def addstr(self, y, x, text, *args):
        self.writes.append((y, x, text, args))

    def getch(self):
        return next(self.keys)

    def erase(self):
        self.erase_calls += 1

    def refresh(self):
        self.refresh_calls += 1


def _disable_cursor(monkeypatch):
    monkeypatch.setattr(curses, "curs_set", lambda *_args: None)


def test_confirm_accepts_yes_no_and_uppercase(monkeypatch):
    _disable_cursor(monkeypatch)
    for key, expected in ((ord("y"), True), (ord("Y"), True), (ord("n"), False), (ord("N"), False)):
        screen = FakeScreen([key])
        assert screens.confirm(screen, "Continue?") is expected
        assert screen.erase_calls == 1
        assert screen.refresh_calls >= 1


def test_confirm_enter_accepts_displayed_default(monkeypatch):
    _disable_cursor(monkeypatch)
    assert screens.confirm(FakeScreen([ord("\n")]), "Continue?") is True
    assert screens.confirm(FakeScreen([curses.KEY_ENTER]), "Continue?", default=False) is False


def test_confirm_repaints_without_stale_previous_screen(monkeypatch):
    _disable_cursor(monkeypatch)
    screen = FakeScreen([ord("y")])
    assert screens.confirm(screen, "Use this pool?") is True
    visible = " ".join(text for _y, _x, text, _args in screen.writes)
    assert "Use this pool?" in visible
    assert "Enter = Yes" in visible
    assert screen.erase_calls == 1


def test_choice_clears_previous_prompt_before_rendering(monkeypatch):
    _disable_cursor(monkeypatch)
    screen = FakeScreen([ord("\n")])
    assert screens.get_choice(screen, "Choose role:", ["Master", "Worker"]) == 0
    assert screen.erase_calls == 1


def test_choice_renders_intro_explanation(monkeypatch):
    _disable_cursor(monkeypatch)
    screen = FakeScreen([ord("\n")])
    intro = [
        "Choose how this computer will be used in Lattice.",
        "Master: The main computer. It manages the fleet, approves new computers,",
        "and shows overall status.",
        "Worker: A computer that joins the Master and becomes part of the fleet.",
        "Usually, you have one Master and the rest are Workers.",
    ]
    assert screens.get_choice(
        screen, "Choose role:", ["Master", "Worker"], intro_lines=intro
    ) == 0
    visible = " ".join(text for _y, _x, text, _args in screen.writes)
    for line in intro:
        assert line in visible
    assert "Choose role:" in visible

def test_confirm_keeps_context_visible(monkeypatch):
    _disable_cursor(monkeypatch)
    screen = FakeScreen([ord("\n")])
    context = [
        "Detected network settings:",
        "Gateway: 10.77.0.1",
        "Subnet mask: 255.255.255.0",
    ]
    assert screens.confirm(
        screen,
        "Use these detected network settings?",
        context_lines=context,
    ) is True
    visible = " ".join(text for _y, _x, text, _args in screen.writes)
    for line in context:
        assert line in visible
    assert "Use these detected network settings?" in visible
    assert "Enter = Yes" in visible


def test_master_completion_never_displays_api_token_source_text():
    source = Path("lattice/wizard/orchestration.py").read_text()
    assert 'center_text(stdscr, f"API token: {api_token}"' not in source
    assert "shown once, save it now" not in source
    assert "Authentication credentials were generated and stored securely." in source
    assert "You do not need to save them manually." in source


def test_wizard_major_steps_clear_stale_screen_content():
    source = Path("lattice/wizard/orchestration.py").read_text()
    for marker in (
        "def welcome_step",
        "def ip_step",
        "def network_step",
        "def static_ip_step",
        "def ssh_firewall_step",
        "def ssh_key_step",
        "def key_exchange_step",
        "def write_start_step",
    ):
        start = source.index(marker)
        end = source.find("\ndef ", start + 5)
        block = source[start : end if end != -1 else len(source)]
        assert "stdscr.erase()" in block, marker


def test_master_first_run_does_not_scan_for_workers_automatically():
    source = Path("lattice/wizard/orchestration.py").read_text()
    master_start = source.index('    master_user = os.environ.get("SUDO_USER")')
    master_end = source.index("\ndef write_start_step", master_start)
    master_block = source[master_start:master_end]
    assert "discover_waiting_workers" not in master_block
    assert "Searching for workers waiting to be paired" not in master_block
    assert "Lattice Master setup complete." in master_block
    assert "Your Master is installed, configured, and running." in master_block
    assert "Opening the Lattice dashboard..." in master_block
    assert "Press any key to continue." in master_block
    assert "Set up a Worker next" not in master_block
    assert "lattice workers add" not in master_block


def test_final_completion_clears_before_rendering():
    source = Path("lattice/wizard/orchestration.py").read_text()
    completion = source.index('center_text(stdscr, "✅ Lattice setup complete!"')
    preceding = source[max(0, completion - 120):completion]
    assert "stdscr.erase()" in preceding


def test_ssh_key_helper_never_prints_into_curses_terminal():
    source = Path("lattice/core/crypto/ssh.py").read_text()
    assert "print(" not in source


def test_master_init_enters_existing_lattice_tui_after_setup():
    source = Path("lattice/cli/main.py").read_text()
    assert 'if current_role() == "master" and os.path.exists(CONFIG_PATH):' in source
    assert "return _run_main_tui()" in source
    assert "run_tui(status)" in source
    assert "from lattice.cli.worker_tui" not in source
    assert "actions = [" not in source[source.index("def _run_main_tui"):source.index("def cmd_init")]
    assert "xdg-open" not in source
