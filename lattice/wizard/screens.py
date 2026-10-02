import curses
import logging
import shutil

logger = logging.getLogger(__name__)


def center_text(stdscr, text, y=None):
    h, w = stdscr.getmaxyx()
    if y is None:
        y = h // 2
    x = (w - len(text)) // 2
    if x < 0:
        x = 0
    stdscr.addstr(y, x, text[:w-1])


def get_string(stdscr, prompt, default=""):
    h, w = stdscr.getmaxyx()
    center_text(stdscr, prompt, h//2 - 1)
    if default:
        center_text(stdscr, f"[default: {default}]", h//2 + 1)
    curses.echo()
    stdscr.move(h//2, 2)
    stdscr.clrtoeol()
    inp = stdscr.getstr(h//2, 2, w-4).decode('utf-8').strip()
    curses.noecho()
    return inp if inp else default


def get_choice(stdscr, prompt, options, default=0, intro_lines=None):
    curses.curs_set(0)
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    intro_lines = intro_lines or []
    intro_start = max(1, h//2 - len(options)//2 - len(intro_lines) - 5)
    for offset, line in enumerate(intro_lines):
        center_text(stdscr, line, intro_start + offset)
    center_text(stdscr, prompt, h//2 - len(options)//2 - 2)
    selected = default
    while True:
        for i, opt in enumerate(options):
            y = h//2 - len(options)//2 + i
            x = (w - len(opt)) // 2
            if i == selected:
                stdscr.addstr(y, x, opt, curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, opt)
        stdscr.refresh()
        key = stdscr.getch()
        if key == ord('q'):
            return -1
        if key == curses.KEY_UP:
            selected = (selected - 1) % len(options)
        elif key == curses.KEY_DOWN:
            selected = (selected + 1) % len(options)
        elif key in (ord('\n'), ord('\r'), curses.KEY_ENTER):
            return selected


def confirm(stdscr, prompt, default=True, context_lines=None):
    """Show an isolated yes/no prompt with persistent explanatory context."""
    curses.curs_set(0)
    stdscr.erase()
    h, _w = stdscr.getmaxyx()
    context_lines = context_lines or []
    context_start = max(1, h//2 - len(context_lines) - 3)
    for offset, line in enumerate(context_lines):
        center_text(stdscr, line, context_start + offset)
    center_text(stdscr, prompt, h//2)
    hint = "[Y]es / [n]o  (Enter = Yes)" if default else "[y]es / [N]o  (Enter = No)"
    center_text(stdscr, hint, h//2 + 2)
    stdscr.refresh()
    while True:
        key = stdscr.getch()
        if key in (ord('y'), ord('Y')):
            return True
        if key in (ord('n'), ord('N')):
            return False
        if key in (ord('\n'), ord('\r'), curses.KEY_ENTER):
            return default
